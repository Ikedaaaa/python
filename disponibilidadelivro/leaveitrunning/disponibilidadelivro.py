import configparser
import logging
import smtplib
from email.message import EmailMessage
import requests
from datetime import date

def getRequestExceptionString(url, data):
    return f"An exception occurred during request to URL:\n{url}\nWith request data:\n{data}\n"

def isDifferentPrice(differentPrices, newPrice):
    for differentPrice in differentPrices:
        if newPrice == differentPrice[1]:
            return False
    return True

def getEmailCfg():
    try:
        config_parser = configparser.RawConfigParser()
        config_filepath = r'email.cfg'
        config_parser.read(config_filepath)

        return (
            config_parser.get('EMAIL', 'mailto'),
            config_parser.get('EMAIL', 'mailfrom'),
            config_parser.get('EMAIL', 'pwd')
        )
    except Exception as e:
        logging.exception("Error reading file email.cfg")
        return "", "", ""

def buildEmailBody(p_bookName, p_availableForSale, p_errorCode, p_isAvailable, p_differentPrices):
    price_string = """"""
    if len(p_differentPrices) == 1:
        price_string = f"""
        <p><b>PRICE</b></p>
        <p>R${'%.2f' % p_differentPrices[0][1]}</p>
        """
    else:
        price_string = f"""
        <p><b>PRICES</b></p>
        """
        for differentPrice in p_differentPrices:
            price_string += f"""<p><b>{differentPrice[0]}</b>: R${'%.2f' % differentPrice[1]}</p>"""

    corpo_email = f"""
    <p>Hello, your book is available!</p>
    <br/>
    <p><b>Book Name</b>: {p_bookName}</p>
    <p><b>Is Available For Sale</b>: {p_availableForSale}</p>
    <br/>
    <p><b>AVAILABILITY</b></p>
    <p><b>Error Code</b>: {p_errorCode}</p>
    <p><b>Available:</b> {p_isAvailable}</p>
    <br/>
    """ + price_string + """
    <br/>
    <a href=\"https://store.empiricus.com.br/livro-criptomoedas-avulso/\">Check out the offer at the website</a>
    """

    return corpo_email

def buildEmailMessage(p_mailto, p_mailfrom, p_emailbody):
    message = EmailMessage()
    message['Subject'] = "Your book is Available"
    message['From'] = p_mailfrom
    message['To'] = p_mailto
    message.add_header('Content-Type', 'text/html')
    message.set_payload(p_emailbody)

    return message

def sendEmail(bookName, availableForSale, errorCode, isAvailable, differentPrices):
    mailto, mailfrom, pwd = getEmailCfg()
    email_body = buildEmailBody(bookName, availableForSale, errorCode, isAvailable, differentPrices)
    
    msg = buildEmailMessage(mailto, mailfrom, email_body)

    try:
        logging.info(f"Sending email to {mailto}\n")
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(mailfrom, pwd)
            smtp.send_message(msg)
    except Exception as e:
        logging.exception(f"An exception occurred during an attempt to send an email from {mailfrom} to {mailto}")

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

    book_name = offer_items.get("plan_data").get("product_data").get("name")

    if status_code != 200:
        logging.warning(f"Status Code: {status_code}")

    logging.info(f"Book Name: {book_name}")
    logging.warning(f"Error Code: {error_code}")
    logging.warning((f"Available: {available}\n") if is_criptomoedas_request else (f"Available: {available}\n\n"))

    if is_criptomoedas_request and available:
        sendEmail(book_name, is_available_for_sale, error_code, available, different_prices)

# Define new data to create
new_data = {
    "payment_method": "creditCard"
}

today = date.today()

log_filename = f"disponibilidadelivro_{today.year}{today.month:02d}.log"

logging.basicConfig(
    filename=log_filename,
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