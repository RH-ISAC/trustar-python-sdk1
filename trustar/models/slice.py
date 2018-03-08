# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, super
from future import standard_library

# package imports
from .base import ModelBase


class Slice(ModelBase):
    """
    This class models a page of items that would be found in the body of a response from an endpoint that uses
    pagination.

    :ivar items: The list of items of the page; i.e. a list of indicators, reports, etc.
    :ivar page_number: The number of the page out of all total pages, indexed from 0.  i.e. if there are
        4 total pages of size 25, then page 0 will contain the first 25 elements, page 1 will contain the next 25, etc.
    :ivar page_size: The size of the page that was request.  Note that, if this is the last page, then this might
        not equal len(items).  For instance, if pages of size 25 were requested, there are 107 total elements, and
        this is the last page, then page_size will be 25 even though the page only contains 7 elements.
    :ivar has_next: Whether or not a next page exists on the server.
    """

    def __init__(self, items=None, page_number=None, page_size=None, has_next=None):
        self.items = items
        self.page_number = page_number
        self.page_size = page_size
        self.has_next = has_next

    def has_more_pages(self):
        return self.has_next

    @staticmethod
    def from_dict(page, content_type=None):
        """
        Create a |Page| object from a dictionary.  This method is intended for internal use, to construct a
        |Page| object from the body of a response json from a paginated endpoint.

        :param page: The dictionary.
        :param content_type: The class that the contents should be deserialized into.
        :return: The resulting |Slice| object.
        """

        result = Slice(items=page['items'],
                       page_number=page['pageNumber'],
                       page_size=page['pageSize'],
                       has_next=page['hasNext'])

        if content_type is not None:
            if not hasattr(content_type, 'from_dict'):
                raise Exception("content_type parameter must have a 'from_dict' method.")

            result.items = map(content_type.from_dict, result.items)

        return result

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

        d = {
            'items': items,
            'pageNumber': self.page_number,
            'pageSize': self.page_size,
            'hasNext': self.has_next,
        }

        return {k: v for k, v in d.items() if v is not None}

    @staticmethod
    def get_page_generator(func, start_page=0, page_size=None):
        """
        Constructs a generator for retrieving pages from a paginated endpoint.  This method is intended for internal
        use.

        :param func: Should take parameters ``page_number`` and ``page_size`` and return the corresponding |Slice|
        object.
        :param start_page: The page to start on.
        :param page_size: The size of each page.
        :return: A generator instance that can be used to generate each successive slice.
        """

        def generator():

            # initialize starting values
            page_number = start_page
            more_pages = True

            # continuously request the next page as long as more pages exist
            while more_pages:

                # get next slice
                slice = func(page_number=page_number, page_size=page_size)

                yield slice

                # determine whether more pages exist
                more_pages = slice.has_more_pages()
                page_number += 1

        return generator()

    @classmethod
    def get_generator(cls, func=None, page_generator=None):
        """
        Gets a generator for retrieving all results from a paginated endpoint.  Pass exactly one of ``page_generator``
        or ``func``.  This method is intended for internal use.

        :param func: Should take parameters ``page_number`` and ``page_size`` and return the corresponding |Slice|
            object.  If ``page_iterator`` is ``None``, this will be used to create one.
        :param page_generator: A generator to be used to generate each successive |Slice|.
        :return: A generator that generates each successive element.
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

        return iterable()
