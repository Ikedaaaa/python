import requests
import logging

def getRequestExceptionString(url, data):
    return f"Exception occured during request to URL:\n{url}\nWith request data:\n{data}\n"

def isDifferentPrice(differentPrices, newPrice):
    for differentPrice in differentPrices:
        if newPrice == differentPrice[1]:
            return False
    return True 

def logResponseData(response_data):
    prices = []
    different_prices = []

    status_code = response_data.status_code
    response_data_json = response_data.json()

    is_available_for_sale = response_data_json.get("cart").get("offer").get("is_available_for_sale")
    availability = response_data_json.get("cart").get("offer").get("availability")
    offer_items = response_data_json.get("cart").get("offer").get("offer_items")[0]

    prices.append(['cart.offer.price', response_data_json.get("cart").get("offer").get("price")])
    prices.append(['cart.offer.offer_price.price', response_data_json.get("cart").get("offer").get("offer_price")[0].get("price")])
    prices.append(['cart.offer.offer_items.price', offer_items.get("price")])
    prices.append(['cart.offer.offer_items.plan_data.price', offer_items.get("plan_data").get("price")])

    for idx, price in enumerate(prices):
        if idx == 0:
            different_prices.append(price)
        else:
            if isDifferentPrice(different_prices, price[1]):
                different_prices.append(price)

    bookName = offer_items.get("plan_data").get("product_data").get("name")

    print("\n\nStatus Code:",status_code)

    print(f"Book Name: {bookName}\n")

    if len(different_prices) == 1:
        print("PRICE")
        print(f"R${'%.2f' % different_prices[0][1]}")
    else:
        print("PRICES")
        for different_price in different_prices:
            print(f"{different_price[0]}: R${'%.2f' % different_price[1]}")

    print(f"Is Available For Sale: {is_available_for_sale}\n")

    print(f"AVAILABILITY:")
    print(f"Error Code: {availability.get('error_code')}")
    print(f"Available: {availability.get('available')}\n\n")


# Define new data to create
new_data = {
    "payment_method": "creditCard"
}
'''
filename='disponibilidadelivro.log',
    filemode='a',
'''
logging.basicConfig(format='[%(levelname)s] %(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)

#URL "Available = False" at the moment
url_criptomoedas = "https://store-api.empiricus.com.br/commerce/v1/storefront/livro-criptomoedas-avulso"
#Exemplo URL "Available = True" at the moment
url_criptowars = "https://store-api.empiricus.com.br/commerce/v1/storefront/livro-cripto-wars-avulso"

# Request to Criptomoedas book URL
try:
    logging.info(f"Making request to URL {url_criptomoedas}")
    response_criptomoedas = requests.post(url_criptomoedas, json=new_data)
except Exception as e:
    logging.exception(getRequestExceptionString(url_criptomoedas, new_data))

logResponseData(response_criptomoedas)

# Request to Criptowars book URL
try:
    logging.info(f"Making request to URL {url_criptowars}")
    response_criptowars = requests.post(url_criptowars, json=new_data)
except Exception as e:
    logging.exception(getRequestExceptionString(url_criptowars, new_data))

logResponseData(response_criptowars)