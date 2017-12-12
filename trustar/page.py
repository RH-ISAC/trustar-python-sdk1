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

    def __str__(self):
        return json.dumps(self.to_dict())

    def __iter__(self):
        return self.items.__iter__()
