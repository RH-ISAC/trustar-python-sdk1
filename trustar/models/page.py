# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, super
from future import standard_library

# package imports
from .base import ModelBase

# external imports
import math


class Page(ModelBase):
    """
    This class models a page of items that would be found in the body of a response from an endpoint that uses
    pagination.

    :ivar items: The list of items of the page; i.e. a list of indicators, reports, etc.
    :ivar page_number: The number of the page out of all total pages, indexed from 0.  i.e. if there are
        4 total pages of size 25, then page 0 will contain the first 25 elements, page 1 will contain the next 25, etc.
    :ivar page_size: The size of the page that was request.  Note that, if this is the last page, then this might
        not equal len(items).  For instance, if pages of size 25 were requested, there are 107 total elements, and
        this is the last page, then page_size will be 25 even though the page only contains 7 elements.
    :ivar total_elements: The total number of elements on the server, e.g. the total number of elements across all
        pages.  Note that it is possible for this value to change between pages, since data can change between queries.
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

        return math.ceil(float(self.total_elements) / float(self.page_size))

    def has_more_pages(self):
        """
        :return: ``True`` if there are more pages available on the server.
        """

        return self.page_number + 1 < self.get_total_pages()

    def __len__(self):
        return len(self.items)

    @staticmethod
    def from_dict(page):
        """
        Create a |Page| object from a dictionary.  This method is intended for internal use, to construct a
        |Page| object from the body of a response json from a paginated endpoint.

        :param page: The dictionary.
        :return: The resulting |Page| object.
        """

        return Page(items=page['items'],
                    page_number=page['pageNumber'],
                    page_size=page['pageSize'],
                    total_elements=page['totalElements'])

    def to_dict(self, remove_nones=False):
        """
        Creates a dictionary representation of the page.

        :param remove_nones: Whether ``None`` values should be filtered out of the dictionary.  Defaults to ``False``.
        :return: A dictionary representation of the page.
        """

        items = []

        # attempt to replace each item with its dictionary representation if possible
        for item in self.items:
            if hasattr(item, 'to_dict'):
                items.append(item.to_dict(remove_nones=remove_nones))
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
        Constructs a generator for retrieving pages from a paginated endpoint.  This method is intended for internal
        use.

        :param func: Should take parameters ``page_number`` and ``page_size`` and return the corresponding |Page| object.
        :param start_page: The page to start on.
        :param page_size: The size of each page.
        :return: A |GeneratorWithLength| instance that can be used to generate each successive page.
        """

        # python 2 closures cannot mutate data from outer scope
        closure_namespace = {'total_elements': None}

        def iterable():

            # initialize starting values
            page_number = start_page
            more_pages = True

            # continuously request the next page as long as more pages exist
            while more_pages:

                # get next page
                page = func(page_number=page_number, page_size=page_size)
                # update total_elements (it is possible for this to change in between requests)
                closure_namespace['total_elements'] = page.total_elements

                yield page

                # determine whether more pages exist
                more_pages = page.has_more_pages()
                page_number += 1

        def total_elements_getter():
            # if value of 'total_elements' is not cached, need to make call to API
            if closure_namespace['total_elements'] is None:
                # get a page of size 1 (we don't want the actual elements, only the
                # total count, but page of size 0 is not allowed by API) and cache value
                closure_namespace['total_elements'] = func(page_number=0, page_size=1).total_elements

            # return cached value
            return closure_namespace['total_elements']

        return GeneratorWithLength(iterable=iterable(),
                                   total_elements_getter=total_elements_getter)

    @classmethod
    def get_generator(cls, func=None, page_generator=None):
        """
        Gets a generator for retrieving all results from a paginated endpoint.  Pass exactly one of ``page_generator``
        or ``func``.  This method is intended for internal use.

        :param func: Should take parameters ``page_number`` and ``page_size`` and return the corresponding |Page|
            object.  If ``page_iterator`` is ``None``, this will be used to create one.
        :param page_generator: A generator to be used to generate each successive |Page|.
        :return: A |GeneratorWithLength| instance that can be used to generate each successive element.
        """

        # if page_iterator is None, use func to create one
        if page_generator is None:
            if func is None:
                raise Exception("To use 'get_iterator', must provide either a page iterator or a method.")
            else:
                page_generator = cls.get_page_generator(func)

        def iterable():
            # yield each item in the page one by one;
            # once it is out, generate the next page
            for page in page_generator:
                for item in page.items:
                    yield item

        # return a GeneratorWithLength whose __len__ method delegates to that of page_generator
        return GeneratorWithLength(iterable=iterable(),
                                   total_elements_getter=page_generator.__len__)

    def __iter__(self):
        return self.items.__iter__()

    def __getitem__(self, item):
        return self.items[item]


class GeneratorWithLength(object):
    """
    This class models generators that know the total number of elements they will return if iterated over.  It
    is possible that this total number is actually an estimate that will change over time.  Since this class implements
    ``__len__``, the builtin ``len()`` function can be called on its instances.  This class is intended to only be
    instantiated internally.  It is simply meant to provide a way to call ``len()`` on a generator in situations where
    it makes sense to do so.
    """

    def __init__(self, iterable, total_elements_getter):
        self.__iterable = iterable
        self.__total_elements_getter = total_elements_getter
        self.__total_elements = None

    def __iter__(self):
        return self

    def next(self):
        return self.__iterable.next()

    def __next__(self):
        return self.__iterable.__next__()

    def __len__(self):
        return self.__total_elements_getter()
