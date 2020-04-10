import argparse
import copy
import logging
import re
import warnings
from collections import OrderedDict
from functools import reduce
from pathlib import Path
from typing import List, Dict, Union

from confparser.actions import ActionConfFile
from confparser.file_parser import YAMLParser, FileParser
from confparser.types import PathType
from confparser.utils import ifnone, listify

logger = logging.getLogger(__name__)

READ_MODE = 'fr'


class ArgumentParser(argparse.ArgumentParser):
    _reserved = ['_positional', '_flag']

    def __init__(self, *args, **kwargs):
        self._ignored_actions = list()
        self._conf_parsers = OrderedDict()
        super().__init__(*args, **kwargs)

    def parse_args(self, args=None, namespace=None) -> argparse.Namespace:
        # First parsing to get configuration files paths arguments
        with disable_required_args(self):
            known, unknown = super(ArgumentParser, self).parse_known_args(args, namespace)

        # Parse configuration files if present in args
        for k, w in known.__dict__.items():
            parser = self._conf_parsers.get(k)
            if not (parser is None or w is None):
                parser, base = parser
                self.parse_args_from_file(Path(w), ns_name=k, base=base, is_complete=False)

        # Parse all arguments from command-line
        with disable_required_args(self, only_defaults=True):
            args = super(ArgumentParser, self).parse_args(args, namespace)
        return args

    def add_conf_parser(self, arg_name: str, parser=None, base=None):
        self._conf_parsers[arg_name] = (parser, base)
        parser = ifnone(parser, self)
        parser.add_argument('--%s' % arg_name, type=PathType(exists=True, type='file'))
        logger.info('Added `--%s` configuration argument to %s parser' % (arg_name, str(parser.description)))

    def parse_args_from_dict(self, cfg: Dict,
                             ns_name: str = None,
                             base: Union[str, List] = None,
                             is_complete=True):
        """
        Parses config from dict instead of command line
        :param cfg: dict to parse
        :param ns_name: name of returned Namespace if None just returns the basic Namespace
        :param base: which keys of parsed dict should be considered if None it parses whole config dict
        :return: types.SimpleNamespace: An object with all parsed values as nested attributes.
        """
        # Find corresponding nested-dictionary
        if cfg is None: raise ValueError('config is empty for parser %s' % self.description)
        cfg = select_keys(cfg, base, default=cfg)

        # Process all nestsed configs by nested parsers
        # sub_ns = {}
        # for a in self._actions:
        #     # Handle subparsers
        #     if isinstance(a, MyAct):
        #         if a._parser != self:
        #             sub_cfg = get_key(cfg, a._base)
        #             sub_ns.update(a._parser.parse_args_from_dict(sub_cfg, ns_name=a.dest, is_complete=True).__dict__)
        #             # To not consider them next time
        #             del_key(cfg, a._base)
        #         self._ignored_actions.append(a)

        # for a in self._ignored_actions:
        #     self._actions.remove(a)
        #     del self._option_string_actions[a.option_strings[0]]
        #     if a.dest in cfg: del cfg[a.dest]
        # Parse it by self (Parser) to force validation of params
        cfg_str = self._convert_dict_to_args_str(cfg)  # convert dict of args to list
        # Parse string of args representation from config
        if is_complete:
            ns = super(ArgumentParser, self).parse_args(cfg_str)
            if ns_name is not None:
                ns = argparse.Namespace(**{ns_name: ns})
            return ns
        else:
            # Just set defaults
            with disable_required_args(self):
                ns, unknown = super(ArgumentParser, self).parse_known_args(cfg_str)
            self.set_defaults(**ns.__dict__)
        # for k, v in sub_ns.items():
        #     ns.__setattr__(k, v)

        # for a in self._ignored_actions:
        #     self._actions.append(a)

    def parse_args_from_file(self, file: Union[str, Path],
                             cfg_parser: FileParser = None,
                             ns_name: str = None,
                             base: Union[str, List] = None,
                             is_complete=True):
        """
        Parses config from file instead of command line
        :param file: config
        :param cfg_parser: file decoder that parses file to dict (JSON-like structure), if None default
            is YAML parser used
        :param ns_name: name of returned Namespace if None just returns the basic Namespace
        :param base: which keys of parsed dict should be considered if None it parses whole config dict
        :return: types.SimpleNamespace: An object with all parsed values as nested attributes.
        """
        cfg = self._load_cfg_from_path(file, cfg_parser=cfg_parser)
        return self.parse_args_from_dict(cfg, ns_name, base, is_complete)

    def _load_cfg_from_path(self, cfg_path: Path, cfg_parser=None):
        """
        Parses a configuration file yaml given its path.

        Raises:
            ParserError: If there is a parsing error and error_handler=None.
        :param cfg_path: file to read
        :param cfg_parser:
        :return:
        """
        cfg_parser = ifnone(cfg_parser, YAMLParser())
        try:
            cfg = cfg_parser.parse(cfg_path)
        except Exception as e:
            raise e
        return cfg

    def _convert_special_args_to_kwargs(self, cfg):
        """
        Finds proper key value pairs for positional and flag arguments to
        correspond the names from parser (Action.dest).
        :param cfg: initially parsed config from file
        :return: config dict with proper mapping
        """
        pos_args_names = []
        flag_args_names = []
        cfg = copy.deepcopy(cfg)

        for a in self._actions:
            if len(a.option_strings) < 1:
                pos_args_names.append(a.dest)
            if isinstance(a, argparse._StoreTrueAction):
                flag_args_names.append(a.dest)
        # Handle positional args
        # We don't now inner names (dest) of positional args in parser
        # after reading configuration file, we need to get them from parser itself
        for v, k in zip(cfg.get('_positional', []), pos_args_names):
            cfg[k] = v
        cfg.pop('_positional', None)  # delete _positional from the configuration
        # Handle flag args
        for f in cfg.get('_flag', []):
            if f in flag_args_names:
                cfg[f] = True
        cfg.pop('_flag', None)  # delete _positional from the configuration
        return cfg

    def _convert_dict_to_args_str(self, cfg: Dict, src_base: Union[str, List] = None, dest_base=None):
        """
        Converts config dictionary to arguments list formatted alike command-line args
        :param cfg: dict
        :param src_base: which key(s) to parse from the config file if None uses all key of config file
        :param dest_base: which name to use for suffix prepended to outputs of parsing if None no suffix prepended.
            Example:
                dest_base = 'a', each parsed argument will have `a.` suffix, e.g. arg1 -> a.arg1
        :return: list
        """
        kwargs_list = []
        positional_args_list = []
        # warnings.warn('Only accepts flag arguments without value, e.g. one can use '
        #               '-f without following value or --f with following value')
        nested = lambda s: '%s' % s if dest_base is None else '%s.%s' % (dest_base, s)
        src_base_list = listify(ifnone(src_base, list(cfg.keys())))

        for k, v in cfg.items():
            if k not in src_base_list:
                continue

            if k in self._reserved:
                v = listify(v)
                if k == '_positional':
                    positional_args_list.extend([nested(str(val)) for val in v if val is not None])
                elif k == '_flag':
                    kwargs_list.extend(['-%s' % nested(str(val)) for val in v if val is not None])
            else:
                if isinstance(v, Dict):
                    k = None if (dest_base is None and src_base is not None) else nested(k)
                    kwargs_list.extend(self._convert_dict_to_args_str(v, dest_base=k))
                else:
                    k = '--%s' % nested(str(k))
                    v = v if v is None else str(v)
                    kwargs_list.extend([k, v])
        kwargs_list.extend(positional_args_list)

        return kwargs_list

    def _resolve_conf_file_order(self):
        """
        Sorts the ArgumentParser._actions order to be in accordance with:
            [simple_arguments, ActionConfFile arguments].

        Configuration loading could be correctly processed only if
        it's done after all other args are initialized
        :return:
        """
        actions = []
        conf_actions = []
        for a in self._actions:
            if isinstance(a, (ActionConfFile, MyAct)):
                conf_actions.append(a)
            else:
                actions.append(a)
        actions.extend(conf_actions)
        self._actions = actions

    def dump(self, file, ignore_none):
        pass

    def parse_group(self, args, parser: argparse.ArgumentParser, base=''):
        if not (base is None or base == ''):
            args = self.args_without_base(args, base)
        args = parser.parse_args(args)
        return args

    def args_without_base(self, args: List[str], base):
        previous_key = None
        handled_args = []
        for a in args:
            if re.match(r'-{0,2}%s\.' % base, a):  # arg from proper parser
                a = a.replace('%s.' % base, '', 1)  # remove base
                if a.startswith('-'):  # is a named arg's key or flag
                    previous_key = a
                else:  # if positional arg
                    if previous_key is not None:
                        if previous_key.startswith('--'):
                            raise ValueError(
                                'Named option %s needs a value not a positional argument %s' % (previous_key, a))
                        # If previous key was flag, just assign True (pass it)
                        previous_key = None
                handled_args.append(a)
            else:
                if previous_key is not None:  # arg key needs it's value
                    if a.startswith('-'):  # we got a new key of another parser
                        if previous_key.startswith('--'):
                            raise ValueError(
                                'Named option %s needs a value not a positional argument %s' % (previous_key, a))
                    else:
                        handled_args.append(a)
                        previous_key = None
        return handled_args

    def parse_line_to_dict(self, args_list):
        warnings.warn('Parses correctly only flags and named args')
        key = None
        kwargs = {'_positional': []}
        for arg in args_list:
            arg = str(arg)
            if key is None:
                if arg.startswith('--'):
                    key = arg.replace('--', '')
                elif arg.startswith('-'):
                    # WARNING: situation when after flag the positional arg is coming
                    key = arg.replace('-', '')
                else:
                    kwargs['_positional'].append(arg)
            else:
                kwargs[key] = arg
                key = None
        return kwargs


class disable_required_args:
    def __init__(self, parser, only_defaults=False):
        """
        Temporary disables check for required arguments during parsing
        :param parser: which should disable required checks
        :param only_defaults: if True then it disables only args with non-null default values
        """
        self._parser = parser
        self._disabled = set()
        self._only_defaults = only_defaults

    def __enter__(self):
        """
        Открываем подключение с базой данных.
        """
        for a in self._parser._actions:
            if a.required and (not self._only_defaults or (self._only_defaults and a.default is not None)):
                self._disabled.add(a)
                a.required = False
        return self._parser

    def __exit__(self, exc_type, exc_val, exc_tb):
        for a in self._disabled:
            a.required = True
        if exc_val:
            raise


def get_key(d, key, default=None):
    if key is None:
        return default
    return reduce(lambda v, k: v[k], key.split('.'), d)


def del_key(d, key):
    keys = key.split('.')
    v = d
    for k in keys[:-1]:
        v = v[k]
    if keys[-1] in v:
        del v[keys[-1]]
    else:
        raise KeyError("%s not in dict" % k)


def select_keys(d, keys: Union[str, List[str]], default=None):
    """
    Selects set of keys from nested dictionary and returns merged value
        WARNING: if set of nested-dicts has equal subkeys they will be overwritten
    :param d: nested dictionary
    :param keys: dotted nested keys
    :return:
    """
    if keys is None:
        return default
    else:
        sel_d = {}
        keys = listify(keys)
        for k in keys:
            sel_d.update(get_key(d, k, default))
        return sel_d


# class MyAct(argparse.Action):
#     """
#     Use this Action when one wants to specify config loading argument
#     Argument name - name of namespace returned by parsing
#     base - which part of input config to read
#     """
#
#     def __init__(self, *args, parser=None, base=None, **kwargs):
#         self._parser: ArgumentParser = parser
#         self._base = base
#         # self._is_used = False
#         super().__init__(*args, **kwargs)
#
#     def __call__(self, parser: ArgumentParser, namespace, values, option_string=None):
#         is_complete = True
#         if self._parser is None:  # if action pre-initialized without parser keyword, then use calling parser
#             self._parser = parser
#             is_complete = False
#         self._parser._conf_parsers.insert(0, self)
#         setattr(namespace, self.dest, values)
#         # args = self._parser.parse_args_from_file(values, ns_name=self.dest, base=self._base, is_complete=is_complete)
#         # for k, v in args.__dict__.items():
#         #     setattr(namespace, k, v)
#         # self._is_used = True
