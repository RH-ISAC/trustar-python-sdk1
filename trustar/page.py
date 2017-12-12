from __future__ import print_function
from builtins import object
from future import standard_library

import json
import math


class Page(object):
    """
    This class models a page of items that would be found in the body of a response from an
    endpoint that uses pagination.
    """

    def __init__(self, items=None, page_number=None, page_size=None, total_elements=None):
        self.items = items
        self.page_number = page_number
        self.page_size = page_size
        self.total_elements = total_elements

    def get_total_pages(self):
        """
        :return: The total number of pages on the server.
        """
        return math.ceil(self.total_elements / self.page_size)

    def has_more_pages(self):
        """
        :return: True if there are more pages available on the server.
        """
        return self.page_number < self.get_total_pages()

    @staticmethod
    def from_dict(page):
        """
        Instantiate a Page from a dictionary.
        :param page: The dictionary.  A dictionary formed from the response body of a paginated
        endpoint will have the correct format.
        :return: The resulting Page object.
        """
        return Page(items=page['items'],
                    page_number=page['pageNumber'],
                    page_size=page['pageSize'],
                    total_elements=page['totalElements'])

    def to_dict(self):
        """
        Convert a Page to a dictionary.
        :return: The resulting dictionary
        """

        items = []

        # attempt to replace each item with its dictionary representation if possible
        for item in self.items:
            if hasattr(item, 'to_dict'):
                items.append(item.to_dict())
            else:
                items.append(item)

        return {
            'items': items,
            'pageNumber': self.page_number,
            'pageSize': self.page_size,
            'totalElements': self.total_elements
        }

    @staticmethod
    def get_page_generator(func, start_page=0, page_size=None):
        """
        Gets a generator for retrieving pages from a paginated endpoint.
        :param func: Should take parameters 'page_number' and 'page_size' and return the corresponding Page object.
        :param start_page: The page to start on.
        :param page_size: The size of each page.
        :return: A GeneratorWithLength instance that can be used to generate each successive page.
        """

        closure_namespace = {'total_elements': None}

        def iterable():
            page_number = start_page
            more_pages = True
            while more_pages:
                page = func(page_number=page_number, page_size=page_size)
                closure_namespace['total_elements'] = page.total_elements
                yield page
                more_pages = page.has_more_pages()
                page_number += 1

        def total_elements_getter():
            if closure_namespace['total_elements'] is None:
                closure_namespace['total_elements'] = func(page_number=0, page_size=1).total_elements
            return closure_namespace['total_elements']

        return GeneratorWithLength(iterable=iterable(),
                                   total_elements_getter=total_elements_getter)

    @classmethod
    def get_generator(cls, func=None, page_generator=None):
        """
        Gets a generator for retrieving all results from a paginated endpoint.  Pass exactly one of 'page_iterator'
        or 'func'.
        :param func: Should take parameters 'page_number' and 'page_size' and return the corresponding Page object.
        If page_iterator is None, this will be used to create one.
        :param page_generator: A generator to be used to generate each successive page.
        :return: A GeneratorWithLength instance that can be used to generate each successive element.
        """

        # if page_iterator is None, use func to create one
        if page_generator is None:
            if func is None:
                raise Exception("To use 'get_iterator', must provide either a page iterator or a method.")
            else:
                page_generator = cls.get_page_generator(func)

        def iterable():
            for page in page_generator:
                for item in page.items:
                    yield item

        return GeneratorWithLength(iterable=iterable(),
                                   total_elements_getter=page_generator.__len__)

    def __str__(self):
        return json.dumps(self.to_dict())

    def __iter__(self):
        return self.items.__iter__()


class GeneratorWithLength(object):
    """
    This is a wrapper class for generators that also holds a function that can
    be used to get the total number of elements the generator will produce.  It
    is possible that this total number is actually an estimate that will change
    over time.  Since this class implements __len__, the builtin len() function
    can be called on its instances.
    """

    def __init__(self, iterable, total_elements_getter):
        self.__iterable = iterable
        self.__total_elements_getter = total_elements_getter
        self.__total_elements = None

    def __iter__(self):
        return self

    def next(self):
        return self.__iterable.next()

    def __len__(self):
        return self.__total_elements_getter()
