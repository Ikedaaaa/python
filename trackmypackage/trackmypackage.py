import configparser
import logging
import smtplib
from email.message import EmailMessage
import requests

def getRequestExceptionString(url, data):
    return f"An exception occurred during request to URL:\n{url}\nWith request data:\n{data}\n"

def formatDetailOccurrenceInfo(p_last_shipping_details):
    occurrence = p_last_shipping_details['ocorrencia']
    date = p_last_shipping_details['data_ocorrencia']
    return f"Last Occurrence: {occurrence}; Date: {date}\n"

def getCfgFileParams(file_name, section, cfg_params):
    cfg_values = []
    try:
        config_parser = configparser.RawConfigParser()
        config_filepath = file_name
        config_parser.read(config_filepath)

        for cfg_param in cfg_params:
            cfg_values.append(config_parser.get(section, cfg_param))

        return tuple(cfg_values)
    except Exception as e:
        logging.exception(f"Error reading file {file_name}")
        return tuple(cfg_params)

def StillSameOccurrence(p_last_occurreance_code):
    try:
        with open("lastoccurrencedetails.txt", "r") as lastoccurrencedetails_file:
            return lastoccurrencedetails_file.read().split(";")[0] == str(p_last_occurreance_code)
    except FileNotFoundError:
        return False

def WriteLastOccurrenceDetails(p_last_occurrence_details):
    code = p_last_occurrence_details['codigo']
    occurrence_code = p_last_occurrence_details['codigo_ocorrencia']
    occurrence = p_last_occurrence_details['ocorrencia']
    obs = p_last_occurrence_details['obs']
    occurrence_date = p_last_occurrence_details['data_ocorrencia']
    occurrence_dt_registered = p_last_occurrence_details['data_cadastro']
    occurrence_dt_utc = p_last_occurrence_details['data_ocorrencia_dt']

    with open("lastoccurrencedetails.txt", "w") as lastoccurrencedetails_file:
        lastoccurrencedetails_file.write(f"{code};{occurrence_code};{occurrence};{obs};{occurrence_date};{occurrence_dt_registered};{occurrence_dt_utc}")

def buildEmailMessage(p_mailto, p_mailfrom, p_emailbody, package_delivered):
    message = EmailMessage()
    message['Subject'] = "Package Delivered!!" if package_delivered else "New Delivery Status"
    message['From'] = p_mailfrom
    message['To'] = p_mailto
    message.add_header('Content-Type', 'text/html')
    message.set_payload(p_emailbody)

    return message
    
def buildShippingCompanyInfo(general_info):
    #Shipping company info
    empresa = general_info['empresa']
    contato_empresa = general_info['contato_empresa']
    email_empresa = general_info['email_empresa']
    fornecedor_email = general_info['fornecedor_email']
    fornecedor_telefone1 = general_info['fornecedor_telefone_1']

    message = f"""
    <h3>Shipping Company Info</h3>
    <br/>
    <h4>Here's the info of the shipping company, in case you need:</h4>
    <br/>
    <p><b>Company</b>: {empresa}</p>
    <p><b>Company Contact</b>: {contato_empresa}</p>
    <p><b>Company Email</b>: {email_empresa}</p>
    <p><b>Supplier's Email</b>: {fornecedor_email}</p>
    <p><b>Supplier's Phone</b>: {fornecedor_telefone1}</p>
    <br/>
    """

    return message
    
def buildDeliveryTimeline(shipping_details):
    timeline = f"""
    <br/>
    <h3>Delivery Timeline</h3>
    <br/>
    """
    for occurrence in shipping_details:
        timeline += f"""
        <p><b>Date</b>: {occurrence['data_ocorrencia']}</p>
        <p><b>Occurrence</b>: {occurrence['ocorrencia']}</p>
        """
        if occurrence['obs'].strip() != "":
            timeline += f"""
            <p><b>Observation</b>: {occurrence['obs'].strip()}</p>
            """
        
        if occurrence['nome_recebedor'] is not None:
            timeline += f"""
            <p><b>Name</b>: {occurrence['nome_recebedor']}</p>
            <p><b>Document</b>: {occurrence['documento_recebedor']}</p>
            <p><b>Relationship</b>: {occurrence['grau_relacionamento']}</p>
            """

        timeline += f"""
        <p><b>Date of register</b>: {occurrence['data_cadastro']}</p>
        <p><b>UTC Date</b>: {occurrence['data_ocorrencia_dt']}</p>
        <p><b>Occurrence code</b>: {occurrence['codigo_ocorrencia']}</p>
        <br/>
        """

    return timeline
    
def buildGeneralInfo(general_info, p_delivered):
    #**** GENERAL INFO ****
    sender = general_info['remetente']
    service = general_info['servico']
    recipient = general_info['destinatario']
    ultima_ocorrencia = general_info['ultima_ocorrencia']
    situacao = general_info['situacao']

    #Who received
    recebedor = general_info['recebedor']
    recebedor_documento = general_info['recebedor_documento']
    recebedor_parentesco = general_info['recebedor_parentesco']

    message = f""""""
    if p_delivered:
        message =  f"""
        <h3>YOUR PACKAGE HAS BEEN DELIVERED</h3>
        <br/>
        <h4>Info of the person who received your package:</h4>
        <br/>
        <p><b>Name</b>: {recebedor}</p>
        <p><b>Document</b>: {recebedor_documento}</p>
        <p><b>Relationship</b>: {recebedor_parentesco}</p>
        <br/>
        """
        
    message += f"""
    <h3>General Info of the delivery</h3>
    <br/>
    <p><b>Last Occurrence</b>: {ultima_ocorrencia}</p>
    <p><b>Situation</b>: {situacao}</p>
    <br/>
    <p><b>Sender</b>: {sender}</p>
    <p><b>Recipient</b>: {recipient}</p>
    <p><b>Service</b>: {service}</p>
    """
        
    return message

def buildEmailBody(p_general_info, p_shipping_details):
    delivered = p_general_info['recebedor'] is not None
    general_info_body = buildGeneralInfo(p_general_info, delivered)

    delivery_timeline = buildDeliveryTimeline(p_shipping_details)

    shipping_company_info = buildShippingCompanyInfo(p_general_info)

    email_body = f"""
    <div>
    {general_info_body}
    </div>
    <div>
    {delivery_timeline}
    </div>
    <div>
    {shipping_company_info}
    </div>
    """

    return email_body, delivered

def sendEmail(p_general_info, p_shipping_details):
    mailto, mailfrom, pwd = getCfgFileParams(r'email.cfg', 'EMAIL', ['mailto', 'mailfrom', 'pwd'])
    email_body, delivered = buildEmailBody(p_general_info, p_shipping_details)

    msg = buildEmailMessage(mailto, mailfrom, email_body.encode(), delivered)

    try:
        logging.info(f"Sending email to {mailto}\n")
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(mailfrom, pwd)
            smtp.send_message(msg)
    except Exception as e:
        logging.exception(f"An exception occurred during an attempt to send an email from {mailfrom} to {mailto}")

def logResponseData(p_response_data):
    general_info = p_response_data.json()[0][0]
    shipping_details = p_response_data.json()[1]

    if not StillSameOccurrence(shipping_details[0]['codigo']):
        WriteLastOccurrenceDetails(shipping_details[0])
        logging.info(f"NEW UPDATE TO THE STATUS OF THE DELIVERY. {formatDetailOccurrenceInfo(shipping_details[0])}")
        sendEmail(general_info, shipping_details)
    else:
        logging.info(f"No updates on the shipping details. {formatDetailOccurrenceInfo(shipping_details[0])}")

logging.basicConfig(
    filename='trackmypackage.log',
    filemode='a',
    format='[%(levelname)s] %(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.DEBUG
)

url_param, codigo, cpf_cnpj, g_recaptcha_response = getCfgFileParams(r'requestparams.cfg', 'REQUEST', ['url_param', 'codigo', 'cpf_cnpj', 'g-recaptcha-response'])

payload = {'codigo':codigo, 'cpf_cnpj':cpf_cnpj, 'g-recaptcha-response':g_recaptcha_response}

request_url = f"https://www.englobasistemas.com.br/gestao/api/PesquisasExternas/PesquisarPedidosCnpjCpf?{url_param}"

try:
    logging.info(f"Making request to URL {request_url}")
    response_data = requests.post(request_url, data=payload)
    logResponseData(response_data)
except Exception as e:
    logging.exception(getRequestExceptionString(request_url, payload))