from functools import reduce
from typing import Dict


def ifnone(val, optional=None):
    return optional if val is None else val


def listify(val):
    if isinstance(val, (list, tuple)):
        return list(val)
    else:
        return [val]


def dict_to_args(flat_dict: Dict):
    """
    Converts dictionary to list of args: [k0, v0, k1, v1 ...]
    :param flat_dict: of kwargs {arg_name: arg_value}
    :return:
    """
    return list(reduce(lambda x, y: x + y, flat_dict.items()))
