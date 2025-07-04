use crate::auth::validate_token;
use actix_web::{
    Error, HttpResponse,
    body::BoxBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use futures_util::future::{LocalBoxFuture, Ready, ready};
use std::rc::Rc;
use std::task::{Context, Poll};

pub struct Authorization;

impl<S, B> Transform<S, ServiceRequest> for Authorization
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AuthorizationMW<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthorizationMW {
            service: Rc::new(service),
        }))
    }
}

pub struct AuthorizationMW<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for AuthorizationMW<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &self,
        ctx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if req.path() == "/login" || req.path() == "/register" {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res)
            });
        }
        
        if let Some(header) = req.headers().get("Authorization") {
            if let Ok(value) = header.to_str() {
                if value.starts_with("Bearer ") {
                    let token = &value[7..];

                    if validate_token(token) {
                        let fut = self.service.call(req);
                        return Box::pin(async move {
                            let res = fut.await?;
                            Ok(res)
                        });
                    } else {
                        return Box::pin(async move {
                            let res = HttpResponse::Unauthorized().finish();
                            Err(actix_web::error::InternalError::from_response("", res).into())
                        });
                    }
                }
            }
        }

        Box::pin(async move {
            let res = HttpResponse::Unauthorized().finish();
            Err(actix_web::error::InternalError::from_response("", res).into())
        })
    }
}
