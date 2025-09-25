//! Authentication callback handlers for login success and error scenarios.

use crate::api::AuthResponseSuccess;
use parking_lot::Mutex;
use std::sync::Arc;

pub(crate) type OnSuccessInner = Box<dyn FnMut(AuthResponseSuccess) + Send>;

/// The callback executed upon successful login that takes [`AuthResponseSuccess`](crate::api::AuthResponseSuccess) as an argument.
///
/// # Usage
/// ```
/// use ic_auth_client::callback::OnSuccess;
///
/// let on_success = OnSuccess::from(|res| {
///     // Handle successful login
/// });
/// ```
#[derive(Clone)]
pub struct OnSuccess(pub(crate) Arc<Mutex<OnSuccessInner>>);

impl<F> From<F> for OnSuccess
where
    F: FnMut(AuthResponseSuccess) + Send + 'static,
{
    fn from(f: F) -> Self {
        OnSuccess(Arc::new(Mutex::new(Box::new(f))))
    }
}

pub(crate) type OnErrorInner = Box<dyn FnMut(Option<String>) + Send>;

/// The callback executed upon failed login that takes [`Option<String>`](std::option::Option) as an argument.
///
/// # Usage
/// ```
/// use ic_auth_client::callback::OnError;
///
/// let on_error = OnError::from(|err| {
///     // Handle failed login
/// });
/// ```
#[derive(Clone)]
pub struct OnError(pub(crate) Arc<Mutex<OnErrorInner>>);

impl<F> From<F> for OnError
where
    F: FnMut(Option<String>) + Send + 'static,
{
    fn from(f: F) -> Self {
        OnError(Arc::new(Mutex::new(Box::new(f))))
    }
}
