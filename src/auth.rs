
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use std::env;
use uuid::Uuid;


#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String, 
    exp: usize,  
}


pub fn create_token(user_id: Uuid) -> String {
    

    let secret = env::var("JWT_KEY").expect("JWT_KEY must be set in .env");
    
    
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(1))
        .unwrap() 
        .timestamp() as usize; 

    
    let claims = Claims {
        sub: user_id.to_string(), 
        exp: expiration,  
    };

    
    encode(
        &Header::default(), 
        &claims,            
        &EncodingKey::from_secret(secret.as_bytes()), 
    )
    .unwrap() 
}


pub fn validate_token(token: &str) -> bool {

     let secret = env::var("JWT_KEY").expect("JWT_KEY must be set in .env");

    //let secret = "secretkey";
    
    decode::<Claims>(
        token,                                 
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),              
    )
    .is_ok() 
}