﻿Through the API it decodes the payload AES-128 mechanism.
It works in the following way:

.NET CLI

      dotnet add package Aes128Decrypt

post form example:

      <form action="https://mycoolapp.com/Post" method="POST" accept-charset='utf-8'>
      <input type='hidden' name='data' value="PZZDt4FMG5ROVen3bSKJ7zQvF_V5cNRCmn0pfhGzKCIS0OcNcq6WlSXmUPluqY"/>
      </form>

 





c# code:




        using Aes128Decrypt;
        namespace Decrypt
        {
            

             public postdata Post(PayloadData collection)
             {
            
               String app_secret_key = "udhfjgmbdhgteidjfhvhwqas97fj3nfgu3";
        
                var json = collection.PayloadDecrypt(app_secret_key); 

               return json;
            }
        }
        
 

json file is payload data after decoding.

Decoded request example:



    {  
    "Id":1003,
    "lang": "en",
    "returnUrl":"https://app.sbay.sa",
    "AppSettings":{  
      "apiKey":"\"XXX\""
   
    },
    "token":"abcdefghijklmnopqrstuv1234567890"
    }


The application of this type of encryption is usually for highly sensitive transactions such as payments applications and the like.
