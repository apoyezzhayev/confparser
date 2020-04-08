import argparse
import copy
import logging
import re
import warnings
from pathlib import Path
from typing import List, Dict, Union

from confparser.actions import ActionConfFile
from confparser.file_parser import YAMLParser, FileParser
from confparser.utils import ifnone, listify

logger = logging.getLogger(__name__)

READ_MODE = 'fr'


class ArgumentParser(argparse.ArgumentParser):
    _reserved = ['_positional', '_flag']

    def parse_args(self, args=None, namespace=None):
        self._resolve_conf_file_order()
        for a in self._actions:
            # Preload all arguments from parser and set defaults
            # for args parsed from config file by ActionConfFile
            if isinstance(a, ActionConfFile):
                _, _ = super(ArgumentParser, self).parse_known_args(args, namespace)
                break
            # elif isinstance(a, ActionParser):
            #     namespaces[a.dest] = self.parse_group(copy.deepcopy(args), a._parser, base=a.dest)

        # Call parse_args of argparser
        # args, unk = super(ArgumentParser, self).parse_known_args(args, namespace)
        args = super(ArgumentParser, self).parse_args(args)

        # TODO: remove this workaround for reading required args from config files
        # Reset required args from config, which were set in parse_args_from_file
        for a in self._required_from_config:
            a.required = True
        # for k, v in namespaces.items():
        #     args.__setattr__(k, v)
        return args

    def parse_args_from_dict(self, cfg: Dict, ns_name: str = None, base: Union[str, List] = None, only_ns: bool = True):
        """
        Parses config from dict instead of command line
        :param cfg: dict to parse
        :param ns_name: name of returned Namespace if None just returns the basic Namespace
        :param base: which keys of parsed dict should be considered if None it parses whole config dict
        :param only_ns: if True the Namespace is returned if False the default values of parser's actions are set
        :return: types.SimpleNamespace: An object with all parsed values as nested attributes.
        """
        # Parse it by self (Parser) to force validation of params
        cfg_str = self._convert_dict_to_args_str(cfg, src_base=base)  # convert dict of args to list
        if only_ns:
            ns = super(ArgumentParser, self).parse_args(cfg_str)
            if ns_name is not None: ns = argparse.Namespace(**{ns_name: ns})
            return ns
        else:
            parsed, unknown = self.parse_known_args(cfg_str)  # validate by corresponding parser
            cfg = self._convert_special_args_to_kwargs(cfg)  # unified representation of all types of arguments
            # Reset `required` attribute when provided from config file to prevent
            # errors when 'required' arg is not found in command line input.
            self._required_from_config = set()
            for a in self._actions:
                if a.dest in cfg:
                    self._required_from_config.add(a)  # for future reset to True
                    a.required = False
            self.set_defaults(**cfg)  # rewrite parser's defaults by arguments parsed from config file
        # setattr(namespace, self.dest, values)

    def parse_args_from_file(self, file: Union[str, Path],
                             cfg_parser: FileParser = None,
                             ns_name: str = None,
                             base: Union[str, List] = None,
                             only_ns=True):
        """
        Parses config from file instead of command line
        :param file: config
        :param cfg_parser: file decoder that parses file to dict (JSON-like structure), if None default
            is YAML parser used
        :param ns_name: name of returned Namespace if None just returns the basic Namespace
        :param base: which keys of parsed dict should be considered if None it parses whole config dict
        :param only_ns: if True the Namespace is returned if False the default values of parser's actions are set
        :return: types.SimpleNamespace: An object with all parsed values as nested attributes.
        """
        cfg = self._load_cfg_from_path(file, cfg_parser=cfg_parser)
        return self.parse_args_from_dict(cfg, ns_name, base, only_ns)

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
        warnings.warn('Only accepts flag arguments without value, e.g. one can use '
                      '-f without following value or --f with following value')
        nested = lambda s: '%s' % s if dest_base is None else '%s.%s' % (dest_base, s)
        src_base_list = listify(ifnone(src_base, list(cfg.keys())))

        for k, v in cfg.items():
            if k not in src_base_list:
                continue

            if k in self._reserved:
                v = listify(v)
                if k == '_positional':
                    positional_args_list.extend([nested(str(val)) for val in v])
                elif k == '_flag':
                    kwargs_list.extend(['-%s' % nested(str(val)) for val in v])
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
            if isinstance(a, ActionConfFile):
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
