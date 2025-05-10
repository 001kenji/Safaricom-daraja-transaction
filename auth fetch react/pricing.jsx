import {
    LOADING_USER,
    FAIL_EVENT,
    SUCCESS_EVENT,
    SubscriptionPaymentStatusReducer,
    RealoadUserAuthReducer,
    IsloadingPricingPaymentReducer
} from './types'
import Cookies from 'js-cookie'
import { useSelector } from 'react-redux'

export const FetchMakePayments= (props) => async dispatch => {
 
    function AuthFunc(props) {
        const data = props != '' ? JSON.parse(props) : ''
       

        if(!data.success ) {
            console.log('in error zone',data.error)
            var error_message = data.error || 'Seams like the transaction has not been successful. Try agian later.'
            dispatch({
                type : FAIL_EVENT,
                payload : error_message
            })
            dispatch({
                type : SubscriptionPaymentStatusReducer,
                payload : {'status' : 'error','error' : String(error_message)}
            })
            dispatch({
                type : IsloadingPricingPaymentReducer,
                payload : false
            })

        }else if (data.success) {
            const val = JSON.parse(props)
            // dispatch({
            //     type : SUCCESS_EVENT,
            //     payload : val['message']
            // })
            dispatch({
                type : SubscriptionPaymentStatusReducer,
                payload : {'status' : 'success','success' : val['message']}
            })
            dispatch({
                type : RealoadUserAuthReducer,
                payload : true
            })
            dispatch({
                type : IsloadingPricingPaymentReducer,
                payload : false
            })
        }              

    }   

    try{
    
    var myHeaders = new Headers();
    myHeaders.append("Content-Type", "application/json");
    myHeaders.append('Accept', 'application/json')
    if(localStorage.getItem('access') != null){
       // console.log(localStorage.getItem('access') )
        myHeaders.append('Authorization' , `JWT ${localStorage.getItem('access')}`)
        myHeaders.append("x-CSRFToken", `${Cookies.get('Inject')}`);
    }
    
    myHeaders.append("Cookie", `Inject=${Cookies.get('Inject')}`);
 
    var requestOptions = {
        method: 'POST',
        headers: myHeaders,
        redirect: 'follow',
        body : props
      };
    fetch(`${import.meta.env.VITE_APP_API_URL}/app/mpesa_payments/`, requestOptions)
    .then(response => response.text())
    .then(result => AuthFunc(result))
    .catch(error => {
        // dispatch({
        //     type : IsloadingPricingPaymentReducer,
        //     payload : false
        // })
        console.error('There has been a problem with your fetch operation:', error);
      
    });
         
     }catch(err) {
        console.log(err)
        dispatch({
            type : FAIL_EVENT,
            payload : 'An error occured when making your request. Try again later'
        })
        dispatch({
            type : SubscriptionPaymentStatusReducer,
            payload : {'status' : 'error','error' : String(err)}
        })
        dispatch({
            type : IsloadingPricingPaymentReducer,
            payload : false
        })
        
     }





}

