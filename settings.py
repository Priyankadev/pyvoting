import os

MONGO_HOST = os.environ.get('MONGO_HOST', 'ds251245.mlab.com')
MONGO_PORT = os.environ.get('MONGO_PORT', 51245)
MONGO_USERNAME = os.environ.get('MONGO_USERNAME', 'voterixuser')
MONGO_PASSWORD = os.environ.get('MONGO_PASSWORD', 'voterixpass')
MONGO_DNAME = os.environ.get('MONGO_DNAME', 'voterix')


RESOURCE_METHODS = ['GET', 'POST', 'DELETE']

ITEM_METHODS = ['GET', 'PATCH', 'DELETE']

CACHE_CONTROL = 'max-age=20'

CACHE_EXPIRES = 20

URL_PREFIX = 'api'


response = {
    'item_title': 'response',
    'schema': {

        '_id': {
            'type': 'string',
            'required': True,
        },

        'email': {
            'type': 'string',
            'required': True,
        },

        'question': {
            'type': 'string',
            'required': True,
        },

        'answer': {
            'type': 'string',
            'required': True,
        },

        'TimeStamp': {
            'type': 'string',
            'required': True,
        },
    }
}

survey = {
    'item_title': 'survey',
    
    'schema': {
        '_id': {
            'type': 'string',
            'required': True,
        },
        'question': {
            'type': 'string'
        }
    }
}

DOMAIN = {
    'response': response,
    'survey': survey
}


if __name__ == '__main__':
    print('Current setting are')
    print('MONGO_HOST: %s' % MONGO_HOST)
