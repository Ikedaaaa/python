import requests
import logging

def getRequestExceptionString(url, data):
    return f"Exception occured during request to URL:\n{url}\nWith request data:\n{data}\n"

def isDifferentPrice(differentPrices, newPrice):
    for differentPrice in differentPrices:
        if newPrice == differentPrice[1]:
            return False
    return True

def getWriteBookIsAvailableFileDirectory():
    with open("bookavailablefiledirectory.txt", "r") as file:
        return file.read().strip()

def logResponseData(response_data, is_criptomoedas_request=False):
    prices = []
    different_prices = []

    status_code = response_data.status_code
    response_data_json = response_data.json()

    is_available_for_sale = response_data_json.get("cart").get("offer").get("is_available_for_sale")
    availability = response_data_json.get("cart").get("offer").get("availability")
    offer_items = response_data_json.get("cart").get("offer").get("offer_items")[0]

    error_code = availability.get('error_code')
    available = availability.get('available')

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

    if status_code != 200:
        logging.warning(f"Status Code: {status_code}")

    logging.info(f"Book Name: {bookName}")
    logging.warning(f"Error Code: {error_code}")
    if is_criptomoedas_request:
        logging.warning(f"Available: {available}\n")
    else:
        logging.warning(f"Available: {available}\n\n")

    if is_criptomoedas_request and available:
        with open(getWriteBookIsAvailableFileDirectory(), 'w') as write_file:
            write_file.write(f"Book Name: {bookName}\n")
            write_file.write(f"Is Available For Sale: {is_available_for_sale}\n\n")
            write_file.write(f"AVAILABILITY:\n")
            write_file.write(f"Error Code: {error_code}\n")
            write_file.write(f"Available: {available}\n\n")

            if len(different_prices) == 1:
                write_file.write("PRICE\n")
                write_file.write(f"R${'%.2f' % different_prices[0][1]}\n\n")
            else:
                write_file.write("PRICES\n")
                for different_price in different_prices:
                    write_file.write(f"{different_price[0]}: R${'%.2f' % different_price[1]}\n")
                write_file.write("\n\n")

# Define new data to create
new_data = {
    "payment_method": "creditCard"
}

logging.basicConfig(
    filename='disponibilidadelivro.log',
    filemode='a',
    format='[%(levelname)s] %(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.DEBUG
)

#URL "Available = False" at the moment
url_criptomoedas = "https://store-api.empiricus.com.br/commerce/v1/storefront/livro-criptomoedas-avulso"
#Exemplo URL "Available = True" at the moment
url_criptowars = "https://store-api.empiricus.com.br/commerce/v1/storefront/livro-cripto-wars-avulso"

# Request to Criptomoedas book URL
try:
    logging.info(f"Making request to URL {url_criptomoedas}")
    response_criptomoedas = requests.post(url_criptomoedas, json=new_data)
    logResponseData(response_criptomoedas, True)
except Exception as e:
    logging.exception(getRequestExceptionString(url_criptomoedas, new_data))

# Request to Criptowars book URL
try:
    logging.info(f"Making request to URL {url_criptowars}")
    response_criptowars = requests.post(url_criptowars, json=new_data)
    logResponseData(response_criptowars)
except Exception as e:
    logging.exception(getRequestExceptionString(url_criptowars, new_data))