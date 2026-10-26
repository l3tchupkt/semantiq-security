"""Custom repository inheriting from BaseRepository."""

from repositories.base_repo import BaseRepository


class CustomRepository(BaseRepository):
    def find_by_filter(self, filter_val: str):
        """Invoke inherited execute_raw_sql method on self."""
        query = f"SELECT * FROM custom WHERE tag = '{filter_val}'"
        return self.execute_raw_sql(query)
