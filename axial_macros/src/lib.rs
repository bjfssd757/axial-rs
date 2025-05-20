extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input,
    ItemFn,
    LitStr,
    Error,
};

fn parse_single_string_literal_arg(attr_args_ts: TokenStream, macro_name: &str) -> syn::Result<LitStr> {
    match syn::parse::<LitStr>(attr_args_ts) {
        Ok(lit_str) => Ok(lit_str),
        Err(original_error) => {
            Err(Error::new(
                original_error.span(),
                format!("Атрибут #[{}] ожидает один строковый литерал в качестве аргумента, например, #[{}(\"/users\")]", macro_name, macro_name)
            ))
        }
    }
}

#[proc_macro_attribute]
pub fn get(attr_args_ts: TokenStream, item_ts: TokenStream) -> TokenStream {
    let route_path_literal: LitStr = match parse_single_string_literal_arg(attr_args_ts, "get") {
        Ok(lit_str) => lit_str,
        Err(e) => return e.to_compile_error().into(),
    };
    let route_path_value = route_path_literal.value();

    let function_item = parse_macro_input!(item_ts as ItemFn);

    if function_item.sig.asyncness.is_none() {
        return Error::new_spanned(
            function_item.sig.fn_token,
            "Функция-обработчик маршрута должна быть асинхронной (`async fn`).",
        )
        .to_compile_error()
        .into();
    }

    let function_name = &function_item.sig.ident;
    let service_factory_name = function_name.clone();
    let original_function_name = syn::Ident::new(&format!("__original_{}", function_name), function_name.span());

    let mut original_function_logic = function_item.clone();
    original_function_logic.sig.ident = original_function_name.clone();
    original_function_logic.vis = syn::Visibility::Inherited;

    let framework_crate = quote! { axial };

    let expanded_code = quote! {
        #original_function_logic

        #[allow(non_camel_case_types)]
        pub struct #service_factory_name;

        impl #framework_crate::core::routes::router::RouteFactory for #service_factory_name {
            fn register_route_service(self, config: &mut #framework_crate::core::routes::router::RouterConfig) {
                let path_str = #route_path_value;

                let handler_adapter = #framework_crate::core::routes::router::handler_adapters::adapt_responder_fn(
                    #original_function_name
                );

                #framework_crate::core::routes::router::internal_routing::add_route(
                    config,
                    #framework_crate::core::config::configer::Methods::GET,
                    path_str.to_string(),
                    handler_adapter
                );
            }
        }
    };

    TokenStream::from(expanded_code)
}

#[proc_macro_attribute]
pub fn post(attr_args_ts: TokenStream, item_ts: TokenStream) -> TokenStream {
    let route_path_literal: LitStr = match parse_single_string_literal_arg(attr_args_ts, "post") {
        Ok(lit_str) => lit_str,
        Err(e) => return e.to_compile_error().into(),
    };
    let route_path_value = route_path_literal.value();

    let function_item = parse_macro_input!(item_ts as ItemFn);

    if function_item.sig.asyncness.is_none() {
        return Error::new_spanned(
            function_item.sig.fn_token,
            "Функция-обработчик маршрута должна быть асинхронной (`async fn`).",
        )
        .to_compile_error()
        .into();
    }

    let function_name = &function_item.sig.ident;
    let service_factory_name = function_name.clone();
    let original_function_name = syn::Ident::new(&format!("__original_{}", function_name), function_name.span());

    let mut original_function_logic = function_item.clone();
    original_function_logic.sig.ident = original_function_name.clone();
    original_function_logic.vis = syn::Visibility::Inherited;

    let framework_crate = quote! { axial };

    let expanded_code = quote! {
        #original_function_logic

        #[allow(non_camel_case_types)]
        pub struct #service_factory_name;

        impl #framework_crate::core::routes::router::RouteFactory for #service_factory_name {
            fn register_route_service(self, config: &mut #framework_crate::core::routes::router::RouterConfig) {
                let path_str = #route_path_value;
                let handler_adapter = #framework_crate::core::routes::router::handler_adapters::adapt_responder_fn(
                    #original_function_name
                );
                #framework_crate::core::routes::router::internal_routing::add_route(
                    config,
                    #framework_crate::core::config::configer::Methods::POST,
                    path_str.to_string(),
                    handler_adapter
                );
            }
        }
    };
    TokenStream::from(expanded_code)
}

#[proc_macro_attribute]
pub fn put(attr_args_ts: TokenStream, item_ts: TokenStream) -> TokenStream {
    let route_path_literal: LitStr = match parse_single_string_literal_arg(attr_args_ts, "put") {
        Ok(lit_str) => lit_str,
        Err(e) => return e.to_compile_error().into(),
    };
    let route_path_value = route_path_literal.value();

    let function_item = parse_macro_input!(item_ts as ItemFn);

    if function_item.sig.asyncness.is_none() {
        return Error::new_spanned(
            function_item.sig.fn_token,
            "Функция-обработчик маршрута должна быть асинхронной (`async fn`).",
        )
        .to_compile_error()
        .into();
    }

    let function_name = &function_item.sig.ident;
    let service_factory_name = function_name.clone();
    let original_function_name = syn::Ident::new(&format!("__original_{}", function_name), function_name.span());

    let mut original_function_logic = function_item.clone();
    original_function_logic.sig.ident = original_function_name.clone();
    original_function_logic.vis = syn::Visibility::Inherited;

    let framework_crate = quote! { axial };

    let expanded_code = quote! {
        #original_function_logic

        #[allow(non_camel_case_types)]
        pub struct #service_factory_name;

        impl #framework_crate::core::routes::router::RouteFactory for #service_factory_name {
            fn register_route_service(self, config: &mut #framework_crate::core::routes::router::RouterConfig) {
                let path_str = #route_path_value;
                let handler_adapter = #framework_crate::core::routes::router::handler_adapters::adapt_responder_fn(
                    #original_function_name
                );
                #framework_crate::core::routes::router::internal_routing::add_route(
                    config,
                    #framework_crate::core::config::configer::Methods::PUT,
                    path_str.to_string(),
                    handler_adapter
                );
            }
        }
    };
    TokenStream::from(expanded_code)
}
