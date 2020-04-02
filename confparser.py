import logging
import os
from pathlib import Path
from typing import Dict

import yaml

logger = logging.getLogger(__name__)

READ_MODE = 'fr'


def ifnone(val, optional=None):
    return optional if val is None else val


class Parser:
    def __init__(self):
        pass

    def load_cfg_from_dict(self, cfg: Dict):
        pass

    def load_cfg_from_path(self, cfg_path: str,
                           parser=None):
        """Parses a configuration file yaml given its path.

        Args:
            cfg_path (str or Path): Path to the configuration file to parse.
            ext_vars (dict): Optional external variables used for parsing jsonnet.
            env (bool or None): Whether to merge with the parsed environment. None means use the ArgumentParser's default.
            defaults (bool): Whether to merge with the parser's defaults.
            nested (bool): Whether the namespace should be nested.
            with_meta (bool): Whether to include metadata in config object.

        Returns:
            types.SimpleNamespace: An object with all parsed values as nested attributes.

        Raises:
            ParserError: If there is a parsing error and error_handler=None.
        """
        fpath = Path(cfg_path, mode=READ_MODE)
        parser = ifnone(parser, YAMLParser())
        if not fpath.is_url:
            cwd = os.getcwd()
            os.chdir(os.path.abspath(os.path.join(fpath(absolute=False), os.pardir)))
        try:
            data = parser.parse(fpath)
            cfg = self.load_cfg_from_dict(data)
        finally:
            if not fpath.is_url:
                os.chdir(cwd)

        logger.info('Parsed file from path: %s', cfg_path)

        return cfg


class FileParser:
    def parse(self, file):
        pass


class YAMLParser(FileParser):
    def parse(self, file):
        try:
            f = file.get_content()
            data = yaml.safe_load(f)
            return data
        except Exception as ex:
            raise type(ex)('Problems parsing config :: ' + str(ex))
