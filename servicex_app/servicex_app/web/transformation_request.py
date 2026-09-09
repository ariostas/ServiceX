from flask import render_template, current_app, request

from servicex_app.decorators import oauth_required
from servicex_app.models import LogMessage
from servicex_app.resources.servicex_resource import ServiceXResource


@oauth_required
def transformation_request(id_: str):
    current_app.logger.debug(f"Got transformation request: {id_}")
    req = ServiceXResource.get_owned_request(id_)

    page = request.args.get("page", 1, type=int)
    log_level = request.args.get("log_level", "").upper()
    # An unrecognized level is no filter at all, not an empty result.
    min_level = LogMessage.LEVELS.get(log_level)

    query = LogMessage.query.filter_by(request_id=req.request_id)
    if min_level is None:
        log_level = None
    else:
        # The filter is a minimum severity: this level and everything above it.
        query = query.filter(LogMessage.level_no >= min_level)

    logs = query.order_by(LogMessage.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )

    return render_template(
        "transformation_request.html",
        req=req,
        logs=logs,
        log_levels=LogMessage.LEVELS,
        active_level=log_level,
    )
