from typing import Dict

import yaml


class FileParser:
    def parse(self, file):
        pass


class YAMLParser(FileParser):
    def parse(self, file):
        try:
            with open(file, 'r') as f:
                data = yaml.safe_load(f)
            return data
        except Exception as ex:
            raise type(ex)('Problems parsing config :: ' + str(ex))

    def dump(self, d: Dict, file):
        try:
            with open(file, 'w') as f:
                yaml.safe_dump(d, f)
                print('Saved to %s' % file)
        except Exception as ex:
            raise type(ex)('Problem with saving :: ' + str(ex))
