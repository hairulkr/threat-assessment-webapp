import json
import os
from datetime import datetime

class DailyUsageTracker:
    def __init__(self, file_path="usage_tracker.json", daily_limit=25):
        self.file_path = file_path
        self.daily_limit = daily_limit
        self.usage_data = self._load_usage_data()

    def _load_usage_data(self):
        try:
            safe_path = os.path.abspath(self.file_path)
            if not safe_path.endswith('.json'):
                raise ValueError("Invalid file type")
            with open(safe_path, "r") as file:
                data = json.load(file)
                # Validate data structure
                if not isinstance(data, dict) or "date" not in data or "count" not in data:
                    raise ValueError("Invalid data format")
                return data
        except (FileNotFoundError, json.JSONDecodeError, ValueError):
            return {"date": None, "count": 0}

    def _save_usage_data(self):
        with open(self.file_path, "w") as file:
            json.dump(self.usage_data, file)

    def increment_usage(self):
        today = datetime.now().strftime("%Y-%m-%d")
        if self.usage_data.get("date") != today:
            self.usage_data = {"date": today, "count": 0}
        
        if self.usage_data["count"] < self.daily_limit:
            self.usage_data["count"] += 1
            self._save_usage_data()
            return True
        return False

    def get_remaining_tries(self):
        today = datetime.now().strftime("%Y-%m-%d")
        if self.usage_data.get("date") != today:
            return self.daily_limit
        return self.daily_limit - self.usage_data["count"]

# Example usage
if __name__ == "__main__":
    tracker = DailyUsageTracker()
    if tracker.increment_usage():
        print("Try recorded. Remaining tries:", tracker.get_remaining_tries())
    else:
        print("Daily limit reached. Try again tomorrow.")