# Copyright (c) 2019, IRIS-HEP
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from typing import Optional

from importlib.metadata import version, PackageNotFoundError
from flask import current_app, g, session
from flask_jwt_extended import get_jwt_identity
from flask_restful import Resource, abort
from servicex_app.advertised_endpoint import advertised_endpoint
from servicex_app.models import UserModel, TransformRequest

from servicex_app.decorators import jwt_required_if_auth_enabled


class ServiceXResource(Resource):
    def __init__(self):
        """
        Initialize object
        """
        super().__init__()

    @classmethod
    def _generate_advertised_endpoint(cls, endpoint):
        return advertised_endpoint(endpoint)

    @staticmethod
    def get_requesting_user() -> Optional[UserModel]:
        """
        :return: User who submitted request for resource.
        If auth is enabled, this cannot be None for JWT-protected resources
        which are decorated with @auth_required or @admin_required.
        """
        # @auth_required has already verified the token and loaded the user
        if "requesting_user" in g:
            return g.requesting_user
        return ServiceXResource._find_requesting_user()

    @staticmethod
    @jwt_required_if_auth_enabled(optional=True)
    def _find_requesting_user() -> Optional[UserModel]:
        user = None
        if current_app.config.get("ENABLE_AUTH"):
            if session.get("is_authenticated"):
                user_id = session.get("user_id")
                if user_id is not None:
                    user = UserModel.find_by_id(user_id)
            else:
                user = UserModel.find_by_email(get_jwt_identity())
        return user

    @classmethod
    def get_owned_request(cls, request_id) -> TransformRequest:
        """
        Look up a transform request and confirm that the requesting user is
        allowed to act on it, i.e. auth is disabled, or they are an admin or
        the submitter.
        :return: The transform request.
        :raises HTTPException: 404 if there is no such request, 403 if the
        requesting user may not access it.
        """
        transform_req = TransformRequest.lookup(request_id)
        if not transform_req:
            msg = f"Transformation request not found with id: {request_id}"
            current_app.logger.warning(msg, extra={"request_id": request_id})
            abort(404, message=msg)

        if current_app.config.get("ENABLE_AUTH"):
            user = cls.get_requesting_user()
            if not user or (not user.admin and user.id != transform_req.submitted_by):
                msg = "You are not authorized to access this request"
                current_app.logger.warning(msg, extra={"request_id": request_id})
                abort(403, message=msg)

        return transform_req

    @classmethod
    def _get_app_version(cls):
        """
        Examine installed packages to get the version number for the ServiceX App
        :return: The version number, or the string "develop" if servicex_app not installed
        """
        try:
            return version("servicex_app")
        except PackageNotFoundError:
            return "develop"
