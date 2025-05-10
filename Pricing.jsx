import React, { useEffect, useLayoutEffect, useRef, useState } from "react";
import { connect, useDispatch, useSelector } from "react-redux";
import { FetchMakePayments } from "../actions/pricing";
import { useNavigate, useParams } from "react-router-dom";
import {PaymentElement, CardElement, useStripe, useElements} from '@stripe/react-stripe-js';
import { IoPhonePortraitOutline } from "react-icons/io5";
import {useForm} from 'react-hook-form'
import { FetchUserProfile } from "../actions/profile";
import "video-react/dist/video-react.css";
import { MdQuestionMark } from "react-icons/md";
import { CiUser } from "react-icons/ci";
import {PaystackButton} from 'react-paystack'
import { IoCloseOutline,IoPersonOutline,IoCardOutline,IoCalendarOutline,IoLockClosedOutline,IoCashOutline } from "react-icons/io5";
import ProfileTestImg from '../assets/images/fallback.jpeg'
import { GiPawn } from "react-icons/gi";
import { GiChessKnight } from "react-icons/gi";
import { GiChessQueen } from "react-icons/gi";
import { GiChessRook } from "react-icons/gi";
import { LuUserRoundX } from "react-icons/lu";
import {toast} from 'react-toastify'
import Cookies from 'js-cookie'
import { FAIL_EVENT, IsloadingPricingPaymentReducer, RealoadUserAuthReducer, ShowLoginContainerReducer, SubscriptionPaymentStatusReducer } from "../actions/types";
const Pricing = ({isAuthenticated,FetchUserProfile,FetchMakePayments}) =>{
    const {register, formState, handleSubmit, getValues, setValue,watch,reset} = useForm({
            defaultValues :{
                'phoneNumber': '',
                'cvc': '',
                'expiryDate' : '',
                'firstName' : '',
                'lastName' : '',
                'cardNumber' : ''

             },
             mode :'all'
        })
    const {errors, isValid,isDirty, isSubmitting, isSubmitted} = formState
   
    const { page, extrainfo } = useParams();
    const dispatch = useDispatch()
    const navigate = useNavigate();
    const db = useSelector((state) => state.auth.user)  
    const UserEmail  = db != null ? db.email : 'gestuser@gmail.com'
    const UserName  = db != null ? db.name : 'Guest'
    const UserID  = db != null ? db.id : import.meta.env.VITE_GEST_USER
    const SubscriptionPaymentStatus = useSelector((state) => state.auth.SubscriptionPaymentStatus)  
    const Isloading = useSelector((state) => state.auth.IsloadingPricingPayment)  
    const [IsLoadingPricing,SetIsLoadingPricing] = useState(false)
    const [ProfilePicturePhoto,SetProfilePicturePhoto] = useState( db != null ? db.ProfilePic : ProfileTestImg)
    const WsDataStream = useRef(null)
    
    const Theme = useSelector((state)=> state.auth.Theme)
    const [ReLoad,SetReLoad] = useState(false)
    const [PricingContainer,SetPricingContainer] = useState({
        'pricing_list' : [],
        'uer_subscription' : null,
        'Billing' : 'monthly',
        'annual_savings_percentage' : '',
        
    })
    const stripe = useStripe();
    const elements = useElements();
    const [PaymentsContainer,SetPaymentsContainer] = useState({
        'phone' : '',
        'amout' : '',
        'stripe_amount' : '',
        'paymentMethod' : 'mpesa',
        'email' : '',
        'show' : false,
        'plan_id' : '',
        'Plan_name' : ''
    })
    useLayoutEffect(()=> {
        requestWsStream('open')
        SetIsLoadingPricing(true)
        if(db != null){
            SetProfilePicturePhoto(db.ProfilePic)
            var data = {
                'scope' : 'ReadProfile',
                'AccountEmail' : UserEmail,
                'AccountID' : UserID,
                'IsOwner' : true,
            }
            
            FetchUserProfile(JSON.stringify([data]))
        }      
    },[db,extrainfo])

    useEffect(() => {
        if(SubscriptionPaymentStatus != null){
            var status_val = SubscriptionPaymentStatus?.status || ''
            if ( status_val == 'success'){
                var success_message = SubscriptionPaymentStatus?.success || ''
                ToongleRadioPaymentValues('show',false)
                if(success_message != ''){
                    ShowToast('success',success_message)
                }
                dispatch({
                        type : SubscriptionPaymentStatusReducer,
                        payload : null
                    })
            }
            
        }
    },[SubscriptionPaymentStatus,Isloading])

    function ShowToast(type,message){
            if(type != null && message != null){
                toast(message,{
                    type : type,
                    theme : Theme,
                    position : 'top-right'
                })
            }
    } 
    const componentProps = {
        email: UserEmail,
        amount: PaymentsContainer.stripe_amount * 100,
        currency: 'KES', // Changed from USD to NGN to avoid currency issues
        metadata: {
            name : `${getValues('firstName')} ${getValues('lastName')}`
        },
        text : IsLoadingPricing ? 'Processing...' : 'Pay Now',
        publicKey : import.meta.env.VITE_PAYSTACK_PUBLISHABLE_KEY,
        onClose: () => {
            // alert("Wait! Don't leave :(")
            SetIsLoadingPricing(false);
        },
        onSuccess : (data) => {
   
            if(data.status == 'success'){
                 handlePaystackVerification(
                    data.reference // Pass the response reference
                );
            }
            ShowToast('success', 'Payment is successful');
        }
    }

    
    const requestWsStream = (msg = null,body = null) => {    
       
        if(msg =='open'){
            if(WsDataStream.current != null ){
                WsDataStream.current.close(1000,'Opening another socket for less ws jam')

            }
            WsDataStream.current =  new WebSocket(`${import.meta.env.VITE_WS_API}/ws/chatList/${UserEmail}/`);

        }
        if(msg == 'close'){
            
            if(WsDataStream.current != null ){
                WsDataStream.current.close(1000,'User-initiated closure')

            }
        }
        
        WsDataStream.current.onmessage = function (e) {
          var data = JSON.parse(e.data)
            setTimeout(() => {
                SetIsLoadingPricing(false)
            }, 2000);
            if(data.type == 'RequestPricingDetails'){
                var message = data.message
                dispatch({
                    type : IsloadingPricingPaymentReducer,
                    payload : false
                })
                if(message.status == 'success'){
                    var pricing_list =  message?.data?.pricing || []
                    var annual_savings_percentage_val = pricing_list[2] ? pricing_list[2]?.annual_savings_percentage || '' : ''
                    
                    SetPricingContainer((e) => {
                        return {
                            ...e,
                            'pricing_list' : pricing_list,
                            'uer_subscription' : message?.data?.userCurrentPlan || null,
                            'annual_savings_percentage' :  `${annual_savings_percentage_val} off`
                        }
                    })
                }else if (message.status == 'error') {
                    SetPricingContainer((e) => {
                        return {
                            ...e,
                            'pricing_list' : [],
                            'uer_subscription' : null,
                            'annual_savings_percentage' : ''
                        }
                    })
                }
            }
        };
        WsDataStream.current.onopen = (e) => {
            // websocket is opened
            
            requestWsStream('RequestPricingDetails')
           
        }
       
        WsDataStream.current.onclose = function (e) {
            // Check if the closure was deliberate (code 1000) or unexpected
            if (e.code === 1000) {
                //   console.log('WebSocket closed intentionally:', e.reason);
                // Optional: Notify user of graceful closure
                // toast('Connection closed', { type: 'info', theme: Theme, position: 'top-right' });
            } else {
            //   console.error('WebSocket disconnected unexpectedly:', e.code, e.reason);
            //   SetOfflineContainer((e) => {
            //     return {
            //         ...e,
            //         'show' : true
            //     }
            //   })
            //   ShowToast('warning','Seams like connection is lost')
            // requestWsStream('open')
              // Reconnect logic (optional)
            setTimeout(() => requestWsStream('open'), 2000); // Reconnect after 3 seconds
            }
        };
        if(WsDataStream.current.readyState === WsDataStream.current.OPEN){
            if(msg == 'RequestPricingDetails') {
                SetIsLoadingPricing(true)
                WsDataStream.current.send(
                    JSON.stringify({
                        'message' : 'RequestPricingDetails',
                        'email' : UserEmail
                    })
                )
            }
            
        }
        
    } 

    function ToongleBilling (scope) {
        if(scope != null ) {
            SetPricingContainer((e) => {
                return {
                    ...e,
                    'Billing' : scope
                }
            })
        }
    }

    const MapPricingFeutures = ({list = []}) => {
        var list_disp = list.map((feature, index) => {
            // console.log(feature)
            var Is_available = feature.value === 'Yes' || typeof feature.value === 'number' ?  true : false
            return (
                <div key={index} className="flex items-start relative overflow-visible">
                    {Is_available ? (
                        <div className="flex flex-row relative gap-1 w-full text-gray-700 dark:text-slate-50" >

                            <svg className="w-5 h-5 text-green-500 my-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                            </svg>
                            <span className=" ">
                                {feature.label}: {feature.value}
                            </span>
                            <button data-tip={feature?.description || ''} className=" cursor-pointer tooltip  tooltip-top mb-auto relative max-w-[100px] " >
                                <MdQuestionMark className=" text-xs dark:text-slate-400 cursor-pointer  " />
                            </button>
                        </div>
                    ) : (
                        <div className="flex flex-row gap-1 w-full text-gray-700 dark:text-slate-400">
                            <svg className="w-5 h-5 text-gray-300 mr-2 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                            </svg>  
                            <span className="">
                                {feature.label}: {feature.value}
                            </span> 
                        </div>
                        
                    )}
                    
                </div>
            )
        })

        return list_disp
    }

    function SubscribeToPlan (plan_name,plan_id,price_val){
        if(UserEmail == 'gestuser@gmail.com'){
            dispatch({
                type: ShowLoginContainerReducer,
                payload : true
            })
            return
        }
        if(plan_name !== 'freemium'){
            console.log('ets')
            // var stripe_amount = Number(price_val) + 1
            SetPaymentsContainer((e) => {
                return {
                    ...e,
                    'show' : true,
                    'email' : UserEmail,
                    'amout' :price_val,
                    'stripe_amount' :price_val,
                    'plan_id' : plan_id,
                    'Plan_name' : plan_name
                }
            })
        }
        
        
    }

    // for updating subscription once payment is done
    const handlePaystackVerification = async () => {
        try {
            ShowToast('info','Initializing yor subscription')
            const paymentData = {
                amount: PaymentsContainer.stripe_amount , // Convert to kobo/cent
                email: UserEmail,
                plan_id: PaymentsContainer.plan_id,
                payment_method: PaymentsContainer.paymentMethod,
                billing_cycle: PricingContainer.Billing || 'monthly',
                name: `${getValues('firstName')} ${getValues('lastName')}`
            };
            const verifyResponse = await fetch(
                `${import.meta.env.VITE_APP_API_URL}/app/paystack/verify/`, 
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `JWT ${localStorage.getItem('access')}`,
                        'x-CSRFToken': Cookies.get('Inject'),
                        "Cookie": `Inject=${Cookies.get('Inject')}`
                    },
                    body: JSON.stringify({
                        ...paymentData
                    })
                }
            );
    
            const verifyResult = await verifyResponse.json();
           
            if ( verifyResult.success) {
                dispatch({
                    type: SubscriptionPaymentStatusReducer,
                    payload: { status: 'success' }
                });
                dispatch({
                    type: RealoadUserAuthReducer,
                    payload: true
                });
                ShowToast('success','Subscription status updated successfuly.')
                // window.location.href = '/payment-complete?status=success';
            } else {
                throw new Error(verifyResult.error || 'Payment verification failed');
            }
        } catch (error) {
            ShowToast('error', error.message);
            dispatch({
                type: SubscriptionPaymentStatusReducer,
                payload: {'status': 'error', 'error': error.message}
            });
        }
    };

    const handleSubmitPayment = () => {
        
        dispatch({
            type : IsloadingPricingPaymentReducer,
            payload : true
        })
        // Prepare base payment data
        const paymentData = {
            amount: PaymentsContainer.amout,
            plan_id: PaymentsContainer.plan_id,
            payment_method: PaymentsContainer.paymentMethod,
            email: UserEmail,
            billing_cycle: PricingContainer.Billing || 'monthly', // Add to your state if needed
        };

        // Add payment method specific data
        paymentData.phone = getValues('phoneNumber'); // From useForm
        console.log(paymentData)
        ShowToast('info','processing your request. Please hold')

        
        FetchMakePayments(JSON.stringify(paymentData,null,3))
    
      
        

    }
    
    const ToongleRadioPaymentValues = (key_val,value_val) => {
        if(key_val != null) {
            SetPaymentsContainer((e) => {
                return {
                    ...e,
                    [key_val] :value_val
                }
            })
        }
        
    }

    const SubscriptionPlans = PricingContainer.pricing_list.map((items,index_val) => {
        var plan = items
        var currentPlanId = PricingContainer.uer_subscription
        // console.log(items)
        var monthly_year_display = plan.name !== 'freemium' ? `${plan.billing_cycles?.monthly.annual_price}/year` : ''
        var annual_year_display = plan.name !== 'freemium' ? `${plan.billing_cycles?.annual.monthly_price}/month (save ${plan.billing_cycles.annual.savings_percentage}%)` : ''
        var price_value = PricingContainer.Billing == 'monthly' ? plan.billing_cycles?.monthly.monthly_price :plan.billing_cycles?.annual.annual_price //plan.billing_cycles?.annual.monthly_price
        var payment_price_value = PricingContainer.Billing == 'monthly' ? plan.billing_cycles?.monthly.monthly_price : plan.billing_cycles?.annual.annual_price
        return (
            <div 
                key={plan.id}
                className={`flex flex-col justify-start gap-2 border-[1px] relative sm:max-w-xs w-full max-w-xs  rounded-2xl p-6 shadow-lg hover:shadow-xl transition-shadow shadow-slate-600 dark:shadow-slate-500 dark:text-white ${
                    plan.id === currentPlanId ? 'shadow-cyan-500 border-transparent ring-[1px] ring-lime-600 dark:ring-sky-300 ' : 'border-gray-200 dark:border-slate-500'
                    }`
                }
              >
               <div className="absolute inset-0 rounded-2xl pointer-events-none min-w-full min-h-full bg-transparent shadow-gray-400/80 dark:shadow-slate-700 shadow-[inset_0_6px_12px_rgba(0,0,0,0.05)]"></div>
                {/* Plan Header */}
                <div className="mb-4">
                    <div className="flex flex-row my-2 w-full gap-3" >
                        <button data-tip={`${plan.display_name} account`} className="tooltip tooltip-right text-lg md:text-xl transition-all duration-300 rounded-full w-8 h-8  shadow-xs shadow-slate-500/50 hover:shadow-slate-500 cursor-pointer dark:shadow-slate-300 dark:hover:shadow-slate-300 " >
                            {
                                plan.name== 'anonymous' ? 
                                    <LuUserRoundX    className=" text-center mx-auto transition-all duration-200 dark:text-amber-300/90  text-black cursor-pointer "  />
                                : plan.name== 'freemium' ? 
                                    <GiPawn className=" text-center mx-auto transition-all duration-200 dark:text-white  text-black cursor-pointer "  />
                                : plan.name== 'standard' ?
                                <GiChessKnight className=" text-center mx-auto transition-all duration-200 dark:text-white text-black cursor-pointer "  />
                                : plan.name== 'professional' ?
                                <GiChessRook className=" text-center mx-auto transition-all duration-200 dark:text-white  text-black cursor-pointer "  />
                                : plan.name== 'enterprise' ?
                                <GiChessQueen className=" text-center mx-auto transition-all duration-200 dark:text-white  text-black cursor-pointer "  />
                                : ''
                            }
                        </button>
                        <h2 className="text-2xl w-fit font-sans font-bold ">{plan.display_name}</h2>
                    </div>
                    <p className="text-sm text-gray-500 dark:text-gray-300 mb-4">
                        {plan.name === 'freemium' ? 'Basic features' : 'For growing businesses'}
                    </p>
                  
                  {/* Price Display */}
                  {plan.name !== 'freemium' ? (
                    <div className="mb-4">
                      <p className="text-5xl font-bold text-gray-900 dark:text-white">
                        ${price_value }
                        <span className="text-sm font-normal text-gray-500 dark:text-gray-300">{PricingContainer.Billing == 'monthly' ? '/month' : '/year'}</span>
                      </p>
                      {plan.billing_cycles?.annual && (
                        <small className="text-xs text-gray-500 dark:text-gray-300 mt-1">
                        ${PricingContainer.Billing == 'monthly' ? monthly_year_display : annual_year_display } 
                        </small>
                      )}
                    </div>
                  ) : (
                    <div className="mb-4">
                      <p className="text-3xl font-bold text-gray-900 dark:text-white">Free</p>
                    </div>
                  )}
                  
                  {/* Current Plan Badge */}
                  {plan.id === currentPlanId && (
                    <span className="inline-block bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded mb-4">
                      Current plan
                    </span>
                  )}
                </div>
                
                {/* Features List */}
                <div className="space-y-3">
                    {<MapPricingFeutures list={items.features}  />}
                </div>
                
                {/* Action Button */}
                <div className={`mt-auto ${plan.name !== 'enterprise' ? '' : 'hidden'} `} >
                    <button onClick={() => plan.id === currentPlanId ? '' : SubscribeToPlan(plan.name,plan.id,payment_price_value)}
                    className={`w-full mt-6 py-2 px-4 rounded-2xl font-medium ${
                        plan.id === currentPlanId
                        ? 'bg-transparent text-gray-700 dark:text-gray-300 cursor-not-allowed'
                        : plan.name === 'freemium'
                        ? 'bg-gray-200 text-gray-700 cursor-pointer hover:bg-gray-300'
                        : 'bg-blue-600 text-white cursor-pointer hover:bg-blue-700'
                    }`}
                    disabled={plan.id === currentPlanId}
                    >
                    {plan.id === currentPlanId ? 'Current Plan' : plan.name === 'freemium' ? 'Get Started' : `Get ${plan.display_name}` }
                    </button>
                </div>
                {/* Action button Enterprise */}
                <div className={` mt-auto ${plan.name == 'enterprise' ? '' : 'hidden'} `} >
                    <button
                    className={`w-full mt-6 py-2 px-4 rounded-md font-medium 
                        bg-transparent cursor-not-allowed text-gray-700 dark:text-gray-400                  
                    }`}
                    disabled={true}
                    >
                    Comming soon
                    </button>
                </div>
                
              </div>
        )
    })
    
  
    // Example usage:
    // <SubscriptionPlans plans={plansData} currentPlanId={2} />
   
    return (
        <div className={`h-full  bg-transparent min-h-full z-40 overflow-x-hidden w-full overflow-y-auto relative min-w-full max-w-[100%] text-black dark:text-slate-100 flex flex-col justify-start  `} >
            {/* top container */}
            <div className="flex w-full sticky z-40 bg-slate-100 dark:bg-slate-900 top-0 flex-col justify-between px-4 py-4 " >
                <h1 className=" font-sans font-semibold text-2xl " >Plans</h1>
                <div className={`flex flex-row justify-between dark:bg-gray-700 bg-gray-200 min-w-fit ml-auto md:mr-2  w-[200px] px-2 py-1 rounded-md`} >
                    <button onClick={() => ToongleBilling('monthly')} className={` cursor-pointer hover:dark:bg-gray-600 hover:bg-gray-300 transition-all duration-300 ${PricingContainer.Billing == 'monthly' ? 'dark:bg-slate-400 bg-slate-50 ' : ' bg-transparent'} p-2 min-w-[60px] text-xs rounded-md `}>Monthly</button>
                    <button onClick={() => ToongleBilling('annual')} className={`cursor-pointer hover:dark:bg-gray-600 hover:bg-gray-300 transition-all duration-300  ${PricingContainer.Billing == 'annual' ? 'dark:bg-slate-400 bg-slate-50 ' : ' bg-transparent'} p-2 min-w-[60px] text-xs rounded-md `}>Yearly {PricingContainer.annual_savings_percentage != '' ? PricingContainer.annual_savings_percentage : ''} </button>
                </div>
                {/* loading container */}
                <span   span className={` ${IsLoadingPricing ? 'opacity-100' : ' opacity-0'} z-40 transition-all duration-300 loading loading-spinner top-full loading-md absolute left-1/2 right-1/2 mx-auto dark:bg-slate-100 bg-slate-900 `}></span>

            </div>
   
            {/* pricing map */}
            <div className="flex flex-row w-full z-30 h-fit flex-wrap justify-around gap-6 p-4">
                {SubscriptionPlans}
            </div>
            {/* payment container */}
            <div className={` ${PaymentsContainer.show ? '' : 'hidden'} w-full max-w-md h-full z-50 flex fixed top-0 right-0 left-0 `} >
                <div className="min-h-fit rounded-2xl flex flex-col gap-3 justify-start m-auto w-full  max-w-[90%] mx-auto h-fittext-black bg-gray-50 dark:bg-gray-700 dark:text-slate-50 py-4 px-4 sm:px-6 lg:px-8">
                    <button onClick={()=> ToongleRadioPaymentValues('show',false)} data-tip='Close' className=" tooltip tooltip-top ml-auto mr-2 " >
                        <IoCloseOutline className="my-auto text-xl transition-all duration-200 dark:text-amber-500 text-amber-700 cursor-pointer "  />
                    </button>
                    <div className="flex flex-col gap-3 max-w-sm w-full mx-auto bg-white   dark:bg-slate-600 rounded-xl shadow-md overflow-hidden  p-6">
                        <h2 className="text-2xl font-bold  mb-6">Make Payment</h2>
                        {/* payment method selector */}
                        <div className={`flex flex-col sm:flex-row justify-start gap-4 w-full h-fit`} >
                                <div className={` ${PaymentsContainer.paymentMethod === 'stripe' ? ' ring-slate-700 dark:ring-slate-400' : ' dark:ring-slate-700 ring-slate-400'} flex flex-row flex-wrap  gap-2 ring-[1px] p-2 rounded-md `} >
                                    <input type="radio" name="radio-9" 
                                        className="radio radio-info  ring-[1px] ring-sky-400 "
                                        checked={PaymentsContainer.paymentMethod === 'stripe'}
                                        onChange={() => ToongleRadioPaymentValues('paymentMethod', 'stripe')}
                                     />
                                     <p className=" font-sans font-semibold " >VISA</p>
                                    
                                </div>
                                <div className={` ${PaymentsContainer.paymentMethod === 'mpesa' ? ' ring-slate-700 dark:ring-slate-400' : ' dark:ring-slate-700 ring-slate-400'} flex flex-row flex-wrap gap-2 ring-[1px] p-2 rounded-md `} >
                                    <input type="radio" name="radio-9" 
                                        className="radio radio-info  ring-[1px] ring-sky-400 "
                                        checked={PaymentsContainer.paymentMethod === 'mpesa'}
                                        onChange={() => ToongleRadioPaymentValues('paymentMethod', 'mpesa')}
                                     />
                                     <p className=" font-sans font-semibold " >M-PESA</p>
                                    
                                </div>
                        </div>
                        <form  className="space-y-4">
                            
                            {/* m-pesa card */}
                            <div className={` ${PaymentsContainer.paymentMethod === 'mpesa' ? ' flex flex-col gap-2' : ' hidden'} w-full`} >
                                <label className=" text-sm " htmlFor="PhoneNumber">By typing your number and selecting the pay button, you will recieve a prompt to enter your Mpesa pin and pay the total amount.</label>
                                <label className="input validator bg-transparent shadow-xs shadow-gray-300 focus-within:outline-none dark:shadow-gray-700">
                                    <IoCashOutline className="h-[1em] opacity-50" /> {/* Currency icon */}
                                    <input
                                        type="text"
                                        className="tabular-nums bg-transparent focus-within:outline-none dark:placeholder:text-slate-300"
                                        readOnly
                                        value={`$ ${PaymentsContainer.amout}`}
                                        placeholder="Amount (KES)"
                                        name="amount"
                                    />
                                </label>                                
                                <label className="input validator bg-transparent shadow-xs shadow-gray-300 focus-within:outline-none dark:shadow-gray-700  ">
                                    <IoPhonePortraitOutline className="h-[1em] opacity-50" />
                                    <input type="tel" 
                                        className="tabular-nums bg-transparent focus-within:outline-none dark:placeholder:text-slate-300 " 
                                        required placeholder="Enter phone number" 
                                        name="PhoneNumber"
                                        {...register('phoneNumber',{
                                            required : 'Please provide a phone number',
                                            minLength: {
                                                value: 12,
                                                message: 'Phone number must be exactly 12 digits (including 254)',
                                              },
                                              maxLength: {
                                                value: 12,
                                                message: 'Phone number must be exactly 12 digits (including 254)',
                                              },
                                              pattern: {
                                                value: /^254\d{9}$/,
                                                message: 'Phone must start with 254 followed by 9 digits (12 total)',
                                              },
                                              validate: {
                                                startsWith254: value => value.startsWith('254') || 'Must start with 254'
                                              }
                                        })}
                                    />
                                </label>
                                {errors.phoneNumber && <p className=" max-w-[600px] bg-transparent text-red-500 dark:text-red-300 text-left ml-4  w-full rounded-sm text-sm sm:text-xs" >{errors.phoneNumber?.message}</p>}
                                
                                {/* Submit Button */}
                                <div>
                                    <button
                                    type="button"
                                    onClick={() =>handleSubmitPayment('submit')}
                                    disabled={Isloading || 
                                        !!(formState.errors.phoneNumber)}
                                    className={`w-full flex justify-center cursor-pointer py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed`}
                                    >
                                    {Isloading ? 
                                        <span className="flex flex-row gap-3 items-center">
                                            <span className="loading loading-spinner loading-lg"></span>
                                            Processing...
                                        </span> 
                                    : 'Pay Now'
                                    }
                                    </button>
                                </div>
                            </div>
                            
                            
                        </form>
                        <div  className="space-y-4">
                            <div className={`${PaymentsContainer.paymentMethod === 'stripe' ? 'flex flex-col gap-2' : 'hidden'} w-full`}>
                                {/* Amount display */}
                                {/* amount */}
                                <label className="input validator bg-transparent shadow-xs shadow-gray-300 focus-within:outline-none dark:shadow-gray-700">
                                    <IoCashOutline className="h-[1em] opacity-50" /> {/* Currency icon */}
                                    <input
                                        type="text"
                                        className="tabular-nums bg-transparent focus-within:outline-none dark:placeholder:text-slate-300"
                                        readOnly
                                        value={`$ ${PaymentsContainer.amout}`}
                                        placeholder="Amount ($)"
                                        name="amount"
                                    />
                                </label>  
                                <label className="input validator bg-transparent shadow-xs shadow-gray-300 focus-within:outline-none dark:shadow-gray-700">
                                    <CiUser  className="h-[1em] opacity-50" /> {/* Currency icon */}
                                    <input
                                    {...register('firstName',{
                                        required : 'First name is required'
                                    })}
                                        type="text"
                                        className="tabular-nums bg-transparent focus-within:outline-none dark:placeholder:text-slate-300"
                                        placeholder="First name"
                                        name="firstName"
                                    />
                                </label>  
                                <label className="input validator bg-transparent shadow-xs shadow-gray-300 focus-within:outline-none dark:shadow-gray-700">
                                    <CiUser  className="h-[1em] opacity-50" /> {/* Currency icon */}
                                    <input
                                    {...register('lastName',{
                                        required : 'Last name is required'
                                    })}
                                        type="text"
                                        className="tabular-nums bg-transparent focus-within:outline-none dark:placeholder:text-slate-300"
                                        placeholder="Last name"
                                        name="lastName"
                                    />
                                </label>  
                                


                                {/* Stripe CardElement */}
                                <div className="my-4 hidden w-full bg-white dark:bg-slate-300  h-fit p-3 border rounded-lg">
                                    <CardElement 
                                        options={{
                                            style: {
                                            base: {
                                                fontSize: '16px',
                                                color: '#424770',
                                                '::placeholder': {color: 'darkslate'},
                                            },
                                            invalid: {
                                                color: '#9e2146',
                                            },
                                            },
                                            hidePostalCode: true
                                        }}
                                    />
                                </div>

                                {/* Submit Button */}
                                <PaystackButton
                                type="button"
                                {...componentProps}
                                    disabled={ IsLoadingPricing}
                                    className="w-full cursor-pointer py-2 px-4 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
                                >
                                    
                                </PaystackButton>
                            </div>
                            
                        </div>

                    </div>
                </div>
            </div>
            
        </div>
    )


}
const mapStateToProps =  state => ({
    isAuthenticated:state.auth.isAuthenticated,
    
}) 
export default connect(mapStateToProps,{FetchUserProfile,FetchMakePayments})(Pricing)