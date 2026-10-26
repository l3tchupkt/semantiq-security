"""Safe custom repository invoking inherited parameterized execution."""

from repositories.base_repo import BaseRepository


class CustomRepository(BaseRepository):
    def find_by_filter(self, filter_val: str):
        query = "SELECT * FROM custom WHERE tag = ?"
        return self.execute_parameterized_sql(query, (filter_val,))
