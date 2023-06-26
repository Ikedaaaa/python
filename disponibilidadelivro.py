import requests

# Define new data to create
new_data = {
    "payment_method": "creditCard"
}

# The API endpoint to communicate with
url_post = "https://store-api.empiricus.com.br/commerce/v1/storefront/livro-criptomoedas-avulso"

# A POST request to tthe API
post_response = requests.post(url_post, json=new_data)

# Print status code from original response (not JSON)
print(post_response.status_code)

# Print the response
post_response_json = post_response.json()

is_available_for_sale = post_response_json.get("cart").get("offer").get("is_available_for_sale")
availability = post_response_json.get("cart").get("offer").get("availability") #.get("available")
offer_items = post_response_json.get("cart").get("offer").get("offer_items")

priceUnder_offer = post_response_json.get("cart").get("offer").get("price")
priceUnder_offer_price = post_response_json.get("cart").get("offer").get("offer_price").get("price")
priceUnder_offer_items = offer_items.get("price")
priceUnder_plan_data = offer_items.get("plan_data").get("price")

bookName = offer_items.get("plan_data").get("product_data").get("name")
