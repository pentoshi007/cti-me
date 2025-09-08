"""
MongoDB database connection and initialization
"""
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, ConfigurationError
import logging

logger = logging.getLogger(__name__)


class MongoDB:
    """MongoDB connection manager"""
    
    client = None
    db = None
    
    @classmethod
    def initialize(cls, app):
        """Initialize MongoDB connection and create indexes"""
        try:
            # Add connection timeout and retry settings
            cls.client = MongoClient(
                app.config['MONGO_URI'],
                serverSelectionTimeoutMS=5000,  # 5 second timeout
                connectTimeoutMS=10000,  # 10 second connection timeout
                socketTimeoutMS=30000,   # 30 second socket timeout
                maxPoolSize=10,          # Maximum connection pool size
                retryWrites=True
            )
            
            cls.db = cls.client.get_database(app.config['MONGO_DB'])
            
            # Test connection with shorter timeout
            cls.client.admin.command('ping')
            logger.info(f"Connected to MongoDB: {app.config['MONGO_DB']}")
            
            # Create collections and indexes
            cls._create_indexes()
            
        except ServerSelectionTimeoutError as e:
            logger.error(f"MongoDB server selection timeout: {e}")
            logger.error("Please check your MongoDB connection string and network connectivity")
            raise
        except ConfigurationError as e:
            logger.error(f"MongoDB configuration error: {e}")
            logger.error("Please check your MongoDB URI format")
            raise
        except ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            logger.error("Please verify MongoDB is running and accessible")
            raise
        except Exception as e:
            logger.error(f"Unexpected error connecting to MongoDB: {e}")
            raise
    
    @classmethod
    def _create_indexes(cls):
        """Create required indexes for all collections"""
        try:
            # Indicators collection indexes
            indicators = cls.db.indicators
            indicators.create_index(["type", "value"], unique=True, background=True)
            indicators.create_index(["last_seen"], background=True)
            indicators.create_index(["severity", "last_seen"], background=True)
            indicators.create_index(["tags", "last_seen"], background=True)
            indicators.create_index(["score"], background=True)
            indicators.create_index(["created_at"], background=True)
            
            # Lookups collection with TTL (30 days)
            lookups = cls.db.lookups
            lookups.create_index(["created_at"], expireAfterSeconds=2592000, background=True)  # 30 days
            lookups.create_index(["user_id", "created_at"], background=True)
            lookups.create_index(["status"], background=True)
            
            # Tags collection
            tags = cls.db.tags
            tags.create_index(["name"], unique=True, background=True)
            tags.create_index(["created_by"], background=True)
            
            # Exports collection with TTL (7 days)
            exports = cls.db.exports
            exports.create_index(["created_at"], expireAfterSeconds=604800, background=True)  # 7 days
            exports.create_index(["created_by", "created_at"], background=True)
            exports.create_index(["status"], background=True)
            
            # Ingest runs collection
            ingest_runs = cls.db.ingest_runs
            ingest_runs.create_index(["source", "started_at"], background=True)
            ingest_runs.create_index(["status"], background=True)
            
            # Enrichment runs collection
            enrichment_runs = cls.db.enrichment_runs
            enrichment_runs.create_index(["operation", "started_at"], background=True)
            enrichment_runs.create_index(["status"], background=True)
            
            # Users collection (for authentication)
            users = cls.db.users
            users.create_index(["username"], unique=True, background=True)
            users.create_index(["email"], unique=True, sparse=True, background=True)
            
            logger.info("Database indexes created successfully")
            
        except Exception as e:
            logger.error(f"Error creating database indexes: {e}")
            # Don't raise here - indexes are not critical for basic functionality
    
    @classmethod
    def get_collection(cls, name: str):
        """Get a MongoDB collection with error handling"""
        if cls.db is None:
            raise RuntimeError("Database not initialized")
        
        try:
            return cls.db[name]
        except Exception as e:
            logger.error(f"Error accessing collection {name}: {e}")
            raise
    
    @classmethod
    def get_database(cls):
        """Get the MongoDB database instance with error handling"""
        if cls.db is None:
            raise RuntimeError("Database not initialized")
        
        try:
            # Test connection
            cls.client.admin.command('ping')
            return cls.db
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            raise
    
    @classmethod
    def test_connection(cls) -> bool:
        """Test MongoDB connection"""
        try:
            if cls.client is None:
                return False
            cls.client.admin.command('ping')
            return True
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
