import pytest


def pytest_addoption(parser):
    parser.addoption('--fuzz', action='store_true', help='run the adapter fuzz campaigns, which need minutes and '
                     'many processes')


def pytest_configure(config):
    config.addinivalue_line('markers', 'fuzz: stateful fuzz of the debug adapters, skipped unless --fuzz is given')


def pytest_collection_modifyitems(config, items):
    if config.getoption('--fuzz'):
        return
    skip = pytest.mark.skip(reason='the adapter fuzzer needs minutes and many processes; pass --fuzz to run it')
    for item in items:
        if item.get_closest_marker('fuzz'):
            item.add_marker(skip)
