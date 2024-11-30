from enum import Enum
import functools
from requests.adapters import HTTPAdapter
import requests
import time
import hashlib
from typing import List, Text

HTTP_MAX_RETRIES = 5


class FilterUrl:
    def __init__(self, filter_url: Text):
        self.filter_url = filter_url

    def url(self) -> Text:
        return self.filter_url

    def hash(self) -> Text:
        return hashlib.sha256(self.filter_url.encode()).hexdigest()


class FilterException(Exception):
    pass


class FilterFetchException(FilterException, requests.exceptions.RequestException):
    pass


class FilterFetchStatusNotOkException(FilterException):
    pass


class FilterGroup(Enum):
    DEFAULT = "default"
    REGIONAL = "regional"
    ADS = "ads"
    PRIVACY = "privacy"
    MALWARE = "malware"
    SOCIAL = "social"


class Filter:
    def __init__(
        self,
        filter_group: FilterGroup,
        url: FilterUrl,
        title: Text,
        enabled_by_default=False,
    ) -> None:
        self.filter_group = filter_group
        self.url = url
        self.title = title
        self.enabled_by_default = enabled_by_default

    def to_dict(self) -> Text:
        return {
            "file_name": f"{self.url.hash()}.txt",
            "title": self.title,
            "group": str(self.filter_group.value),
            "enabled_by_default": self.enabled_by_default,
        }

    def _download(self) -> Text:
        session = requests.Session()

        session.mount("http://", HTTPAdapter(max_retries=HTTP_MAX_RETRIES))
        session.mount("https://", HTTPAdapter(max_retries=HTTP_MAX_RETRIES))

        try:
            response = session.get(f"{self.url.url()}?t={int(time.time())}")
        except requests.exceptions.RequestException as e:
            raise FilterFetchException(e)

        if not response.ok:
            raise FilterFetchStatusNotOkException

        return response.text

    def save_to_registry(self) -> None:
        filter = self._download()

        try:
            with open(f"registry/{self.url.hash()}.txt", "r") as f:
                current_filter = f.read()
        except FileNotFoundError:
            current_filter = ""

        # We strip comments before comparing as some lists
        # are just adding the current timestamp in filter header's comments.
        if _strip_comments_from_filter_list(filter) == _strip_comments_from_filter_list(
            current_filter
        ):
            return

        with open(f"registry/{self.url.hash()}.txt", "w") as f:
            f.write(filter)


def _strip_comments_from_filter_list(filter_list: Text) -> Text:
    filter_list_new = filter_list.splitlines()

    try:
        if filter_list_new[0].startswith("[") and filter_list_new[0].endswith("]"):
            del filter_list_new[0]

    except IndexError:
        return ""

    filter_list_new = [
        filter
        for filter in filter_list_new
        if not filter.startswith("!") and not filter == ""
    ]

    filter_list_new.sort()

    return "\n".join(filter_list_new)


@functools.lru_cache()
def get_filters() -> List[Filter]:
    """
    A filter set mostly derived from https://github.com/gorhill/uBlock/blob/master/assets/assets.json
    """
    return [
        Filter(
            filter_group=FilterGroup.DEFAULT,
            url=FilterUrl(
                "https://CE1CECL.GitHub.io/privaxy.txt"
            ),
            title="ChrisEric1 CECL's filters",
            enabled_by_default=True,
        ),
    ]
