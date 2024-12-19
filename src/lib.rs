//! Simple and reliable tools for dealing with mTLS.
//!
//! This provides utilities for handling various aspects of writing a service that relies on mTLS
//! either directly or sits behind something like Envoy.
pub mod spiffe;
pub mod x_forwarded_clientcert;

#[cfg(test)]
mod tests {
    #[test]
    fn test_access_to_xfcc_helpers() -> Result<(), String> {
        let xfcc_header ="By=http://frontend.lyft.com;Hash=468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688;URI=http://testclient.lyft.com,By=http://backend.lyft.com;Hash=9ba61d6425303443c0748a02dd8de688468ed33be74eee6556d90c0149c1309e;URI=http://frontend.lyft.com";
        match crate::x_forwarded_clientcert::parse_xfcc_list(xfcc_header) {
            Ok(v) => match v.len() {
                2 => Ok(()),
                _ => Err("unexpected number of elements".to_string()),
            },
            Err(e) => Err(format!("error parsing known good value: {:?}", e)),
        }
    }
}
