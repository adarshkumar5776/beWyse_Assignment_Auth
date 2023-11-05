import pymongo

class MongoDBConnection:
    def __init__(self, host="localhost", port=27017, database_name="auth_Db"):
        self.client = pymongo.MongoClient(f"mongodb://{host}:{port}/")
        self.db = self.client[database_name]

    def get_collection(self, collection_name):
        return self.db[collection_name]

    def close_connection(self):
        self.client.close()
