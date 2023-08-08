import json
import logging

import jwt
from django.conf import settings
from graphql import GraphQLError

LOGGER = logging.getLogger('graphene-django-jwt-middleware')

HEALTHCHECK_QUERY = "query __ApolloServiceHealthCheck__ { __typename }"


class JWTAuthorizationMiddleware(object):
    def resolve(self, next, root, info, **args):
        request = info.context

        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        token = auth_header.replace("Bearer ", "")

        if self.is_healthcheck_query(request._body.decode("utf-8")):
            return next(root, info, **args)

        if token:
            valid_token = self.decode_jwt(token)

            if not isinstance(valid_token, GraphQLError):
                return next(root, info, **args)

            return valid_token

        LOGGER.warning(f'JWT Error: {PermissionDenied()}')
        return GraphQLError(PermissionDenied())
    
    def is_healthcheck_query(self, body):
        body = json.loads(body)
        query = body.get("query", "")
        return query == HEALTHCHECK_QUERY

    def decode_jwt(self, token):
        try:
            jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=settings.JWT_ALGORITHMS,
            )
        except jwt.ExpiredSignatureError:
            LOGGER.warning(f'JWT Error: {ExpiredSignatureError()}')
            return GraphQLError(ExpiredSignatureError())
        except jwt.DecodeError:
            LOGGER.warning(f'JWT Error: {DecodeError()}')
            return GraphQLError(DecodeError())
        except jwt.InvalidTokenError:
            LOGGER.warning(f'JWT Error: {InvalidTokenError()}')
            return GraphQLError(InvalidTokenError())
# class TokenAuthGraphQLView(GraphQLView):
#     def dispatch(self, request, *args, **kwargs):
#         auth_header = request.META.get('HTTP_AUTHORIZATION')
#         if valid_header(auth_header):
#             return super().dispatch(request, *args, **kwargs)
#         else:
#             return HttpResponse('Authorization Error', status=401)


# def valid_header(auth_header):
#     return True


class GrapheneDjangoJwtMiddlewareError(Exception):
    default_message = None

    def __init__(self, message=None):
        if message is None:
            message = self.default_message

        super().__init__(message)


class PermissionDenied(GrapheneDjangoJwtMiddlewareError):
    default_message = "You do not have permission to perform this action"


class ExpiredSignatureError(GrapheneDjangoJwtMiddlewareError):
    default_message = "Signature has expired"


class DecodeError(GrapheneDjangoJwtMiddlewareError):
    default_message = "Error decoding token"


class InvalidTokenError(GrapheneDjangoJwtMiddlewareError):
    default_message = "Invalid token"
