from pyramid.response import Response, FileIter, _BLOCK_SIZE


class FileObjResponse(Response):
    """
    A Response object that can be used to serve a static file from disk
    simply.

    ``path`` is a file path on disk.

    ``request`` must be a Pyramid :term:`request` object.  Note
    that a request *must* be passed if the response is meant to attempt to
    use the ``wsgi.file_wrapper`` feature of the web server that you're using
    to serve your Pyramid application.

    ``cache_max_age`` is the number of seconds that should be used
    to HTTP cache this response.

    ``content_type`` is the content_type of the response.

    ``content_encoding`` is the content_encoding of the response.
    It's generally safe to leave this set to ``None`` if you're serving a
    binary file.  This argument will be ignored if you also leave
    ``content-type`` as ``None``.
    """
    def __init__(self, fileobj, request=None, cache_max_age=None,
                 content_type=None, content_encoding=None):
        content_type = 'application/octet-stream'

        super(FileObjResponse, self).__init__(
            conditional_response=True,
            content_type=content_type,
            content_encoding=content_encoding
        )

        app_iter = None
        if request is not None:
            environ = request.environ
            if 'wsgi.file_wrapper' in environ:
                app_iter = environ['wsgi.file_wrapper'](fileobj, _BLOCK_SIZE)
        if app_iter is None:
            app_iter = FileIter(fileobj, _BLOCK_SIZE)
        self.app_iter = app_iter
