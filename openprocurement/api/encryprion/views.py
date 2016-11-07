from pyramid.view import view_config
from .response import FileObjResponse
from .utils import generate_secret_key, encrypt_file, decrypt_file, validate_key
from pyramid.httpexceptions import HTTPBadRequest


@view_config(route_name='generate_key', renderer='json')
def generate_key_view(request):
    return {'key': generate_secret_key()}


@view_config(route_name='encrypt_file', decorator=(validate_key,))
def encrypt_file_view(request):
    key = request.POST.get('key')
    if 'file' not in request.POST:
        raise HTTPBadRequest('Missed file.')
    request.POST.get('file').file.seek(0)
    encrypted_file = encrypt_file(key, request.POST.get('file').file, nonce=request.POST.get('nonce'))
    response = FileObjResponse(encrypted_file)
    response.headers['EncryptionKey'] = key
    return response


@view_config(route_name='decrypt_file', decorator=(validate_key,))
def decrypt_file_view(request):
    key = request.POST.get('key')
    if 'file' not in request.POST:
        raise HTTPBadRequest('Missed encrypted file.')
    request.POST.get('file').file.seek(0)
    try:
        decrypted_file = decrypt_file(key, request.POST.get('file').file)
    except ValueError as e:
        raise HTTPBadRequest(e.message)
    response = FileObjResponse(decrypted_file)
    response.headers['EncryptionKey'] = key
    return response
