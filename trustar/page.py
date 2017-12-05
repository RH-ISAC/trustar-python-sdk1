import json
import math


class Page(object):

    def __init__(self, items=None, page_number=None, page_size=None, total_elements=None):
        self.items = items
        self.page_number = page_number
        self.page_size = page_size
        self.total_elements = total_elements

    def get_total_pages(self):
        return math.ceil(self.total_elements / self.page_size)

    def has_more_pages(self):
        return self.page_number < self.get_total_pages()

    @staticmethod
    def from_dict(page):
        return Page(items=page['items'],
                    page_number=page['pageNumber'],
                    page_size=page['pageSize'],
                    total_elements=page['totalElements'])

    def to_dict(self):
        items = []
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
