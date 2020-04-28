import argparse
import copy
import logging
import re
import warnings
from collections import OrderedDict
from functools import reduce
from pathlib import Path
from typing import List, Dict, Union
from warnings import warn
import sys as _sys

from confparser.file_parser import YAMLParser, FileParser
from confparser.types import PathType
from confparser.utils import ifnone, listify

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

READ_MODE = 'fr'


class ArgumentParser(argparse.ArgumentParser):
    _reserved = ['_positional', '_flag']

    def __init__(self, *args, **kwargs):
        self._conf_parsers = OrderedDict()
        self._ignore_args = set()
        super().__init__(*args, **kwargs)

    # TODO: add support for nested cli arguments
    def parse_args(self, args=None, namespace=None) -> argparse.Namespace:
        if args is None:
            # args default to the system args
            args = _sys.argv[1:]
        # First parsing to get configuration files paths arguments
        with disable_required_args(self):
            known, unknown = super(ArgumentParser, self).parse_known_args(args, namespace)

        # Parse configuration files if present in args
        sub_args = argparse.Namespace()
        for k, w in known.__dict__.items():
            parser_tuple = self._conf_parsers.get(k)
            if parser_tuple is not None and w is not None:
                if not w.exists():
                    logger.warning('File `%s does not exist' % w)
                    continue
                parser, base = parser_tuple
                if parser == self:
                    parser.parse_args_from_file(Path(w), ns_name=k, base=base, is_complete=False)
                else:
                    already_parsed = False
                    if len(parser._conf_parsers) > 0:
                        for _, (sub_parser, base) in parser._conf_parsers.items():
                            if sub_parser == parser:  # only if it has its own config parser
                                sub_args = parser.parse_args_from_file(Path(w), ns_name=k, base=base, is_complete=True)
                                already_parsed = True
                                break
                    if not already_parsed:
                        sub_args = parser.parse_args_from_file(Path(w), ns_name=k, base=base, is_complete=True)

        # Parse all arguments from command-line
        with disable_required_args(self, only_defaults=True):
            args = super(ArgumentParser, self).parse_args(args, namespace)
            for k, v in sub_args.__dict__.items():
                args.__setattr__(k, v)
        return args

    def add_conf_parser(self, arg_name: str, parser=None, base=None):
        """
        Adds configuration parser that reads configuration from file pointed in `--arg_name` cli argument.
        :param arg_name: which argument `--arg_name` will be used to point to configuration file
        :param parser: which parser should parse the configuration file, if None then the parser which
        calls add_conf_parser will be used
        :param base: if configuration file contains many configurations which key to use for parsing
        :return:
        """
        parser = ifnone(parser, self)
        arg_name = re.sub(r'^--?', '', arg_name)  # remove starting - if present
        self._conf_parsers[arg_name] = (parser, base)
        # TODO: add rewrite handling
        self.add_argument('--%s' % arg_name, type=PathType(exists=None, type='file'))
        if parser == self:
            self._ignore_args.add(arg_name)
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
        logger.debug('Loading conf from base %s' % base)
        if cfg is None: raise ValueError('config is empty for parser %s' % self.description)
        selected_cfg = select_keys(cfg, base, default=cfg)

        # Process all nestsed configs by nested parsers
        sub_ns = {}  # sub namespaces
        for dest, (parser, base) in self._conf_parsers.items():
            if parser != self:
                try:
                    get_key(cfg, base)
                except KeyError as e:
                    logger.info('%s not in %s' % (str(e), cfg))
                    continue
                sub_ns.update(parser.parse_args_from_dict(cfg, ns_name=dest, is_complete=False, base=base))
                # To not consider them next time
                del_key(selected_cfg, base.split('.')[-1])

        # Parse it by self (Parser) to force validation of params
        # Parse by basic parsers
        cfg_str = self._convert_dict_to_args_str(selected_cfg)  # convert dict of args to list
        # Parse string of args representation from config
        if is_complete:
            ns = super(ArgumentParser, self).parse_args(cfg_str)
            if ns_name is not None:
                ns = argparse.Namespace(**{ns_name: ns})
        else:
            # Just set defaults
            # with disable_required_args(self):
            #     ns, unknown = super(ArgumentParser, self).parse_known_args(cfg_str)
            ns = self.parse_args(cfg_str)
            ns = ns.__dict__
            ns.update(sub_ns)
            self.set_defaults(**ns)
            if ns_name is not None:
                ns = {ns_name: argparse.Namespace(**ns)}
            # if ns_name is not None:
            #     ns = {ns_name: ns}
        return ns

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
        logger.info('Loading configuration from %s' % file)
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

            if self._is_positional(k):
                positional_args_list.append(nested(v))
            elif k.startswith('flag_'):  # TODO: add proper flags check
                k = k.replace('flag_', '-')
                kwargs_list.append((nested(k), v))
            else:
                if isinstance(v, Dict):
                    k = None if (dest_base is None and src_base is not None) else nested(k)
                    kwargs_list.extend(self._convert_dict_to_args_str(v, dest_base=k))
                else:
                    if v is not None:
                        k = '--%s' % nested(str(k))
                        v = str(v)
                        kwargs_list.extend([k, v])
        kwargs_list.extend(positional_args_list)

        return kwargs_list

    def _is_positional(self, arg_name):
        if arg_name.startswith('positional_'):
            return True
        for a in self._positionals._group_actions:
            if a.dest == arg_name:
                return True

    # def _resolve_conf_file_order(self):
    #     """
    #     Sorts the ArgumentParser._actions order to be in accordance with:
    #         [simple_arguments, ActionConfFile arguments].
    #
    #     Configuration loading could be correctly processed only if
    #     it's done after all other args are initialized
    #     :return:
    #     """
    #     actions = []
    #     conf_actions = []
    #     for a in self._actions:
    #         if isinstance(a, (ActionConfFile, MyAct)):
    #             conf_actions.append(a)
    #         else:
    #             actions.append(a)
    #     actions.extend(conf_actions)
    #     self._actions = actions

    def _resolve_dump(self, args: Dict, ignore):
        tmp_args = args.copy()
        for k, v in args.items():
            if k in self._conf_parsers:
                p, _ = self._conf_parsers[k]
                if p != self:
                    tmp_args[k] = p._resolve_dump(v, ignore)
            if ignore and k in self._ignore_args:
                del tmp_args[k]
        return tmp_args

    def dump(self, args: Union[List, Dict, argparse.Namespace], file: Union[str, PathType], cfg_parser=None,
             ignore=True):
        """

        :param args:
        :param file:
        :param cfg_parser:
        :param ignore:
        :return:
        """
        args = copy.deepcopy(args)
        file = Path(file).absolute()
        if isinstance(args, list):
            args = self.parse_args(args)
        if isinstance(args, argparse.Namespace):
            args = ns_to_dict(args)
        args = self._resolve_dump(args, ignore)
        cfg_parser = ifnone(cfg_parser, YAMLParser())
        # Add warning
        if file.exists():
            logger.info('File %s will be overwritten.' % file)
            warn('Delete previous configuration if you do not want to load presets from it')
        cfg_parser.dump(args, file)
        logger.info('Current configuration saved to %s' % file)

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


def ns_to_dict(ns: argparse.Namespace):
    ns = ns.__dict__
    for k, v in ns.items():
        if isinstance(v, argparse.Namespace):
            ns[k] = ns_to_dict(v)
        elif isinstance(v, Path):
            ns[k] = str(v)
    return ns

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
