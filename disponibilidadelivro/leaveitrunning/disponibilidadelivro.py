import requests
import time
from datetime import datetime

# Define new data to create
new_data = {
    "payment_method": "creditCard"
}

# The API endpoint to communicate with
url_post = "https://store-api.empiricus.com.br/commerce/v1/storefront/livro-criptomoedas-avulso"
#Exemplo URL Available = True
#"https://store-api.empiricus.com.br/commerce/v1/storefront/livro-cripto-wars-avulso"

print(f"Hora antes da requisição: {datetime.now()}")
t1 = time.perf_counter_ns()

# A POST request to the API
post_response = requests.post(url_post, json=new_data)

t2 = time.perf_counter_ns()
print(f"Hora depois da requisição: {datetime.now()}")
print(f"Duração da requisição: {(t2 - t1)/1000000000} segundos\n")

# Print status code from original response (not JSON)
print("Status Code:",post_response.status_code)

# Print the response
post_response_json = post_response.json()

is_available_for_sale = post_response_json.get("cart").get("offer").get("is_available_for_sale")
availability = post_response_json.get("cart").get("offer").get("availability")
offer_items = post_response_json.get("cart").get("offer").get("offer_items")[0]

priceUnder_offer = post_response_json.get("cart").get("offer").get("price")
priceUnder_offer_price = post_response_json.get("cart").get("offer").get("offer_price")[0].get("price")
priceUnder_offer_items = offer_items.get("price")
priceUnder_plan_data = offer_items.get("plan_data").get("price")

bookName = offer_items.get("plan_data").get("product_data").get("name")

print(f"Book Name: {bookName}\n")

print("PRICES:")
print(f"cart.offer.price: R${'%.2f' % priceUnder_offer}")
print(f"cart.offer.offer_price.price: R${'%.2f' % priceUnder_offer_price}")
print(f"cart.offer.offer_items.price: R${'%.2f' % priceUnder_offer_items}")
print(f"cart.offer.offer_items.plan_data.price: R${'%.2f' % priceUnder_plan_data}\n")

print(f"Is Available For Sale: {is_available_for_sale}\n")

print(f"AVAILABILITY:")
print(f"Error Code: {availability.get('error_code')}")
print(f"Available: {availability.get('available')}")
