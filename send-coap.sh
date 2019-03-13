
if [ "$*" == "" ]
then
    coap-client -m get coap://localhost/light

elif [ $1 == "get" ]
then
    coap-client -m get coap://localhost/light
elif [ $1 == "put" ]
then
    if [ $2 == "" ]
    then
        coap-client -m put -e "1" coap://localhost/light
    elif [ $2 == "1" ]
    then
        coap-client -m put -e "1" coap://localhost/light
    elif [ $2 == "0" ]
    then
        coap-client -m put -e "0" coap://localhost/light
    fi

elif [ $1 == "core" ]
then
    coap-client -m get coap://localhost/.well-known/core
fi
