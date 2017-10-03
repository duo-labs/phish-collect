'''Provides a base class for a phishing feed.'''


class Feed(object):
    '''Base class for implementing a new phishing feed'''

    def get(self, offset=0):
        '''
        Returns a list of models.Phish objects representing the new sites we haven't seen
        before

        Args:
            offset {str} - The offset phish ID to send upstream to the service (provider specific ID)
        '''
        raise NotImplementedError


class FetchException(Exception):
    ''' A generic exception class indicating that there was an error fetching the phish feed '''

    def __init__(self, message):
        ''' Creates a new instance of FetchException '''
        super(FetchException, self).__init__(message)
        self.message = message

    def __str__(self):
        ''' Returns the string representation of the error '''
        return self.message