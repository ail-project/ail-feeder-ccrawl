#!/usr/bin/env python
"""
Flask webservice for Common Crawl ClickHouse queries.
Work as API Access for AIL

It provides;

    ** All Uris for a given FQDN ** 
    
    get_uris_for_fqdn, method POST to submit job : List of URIs for a given fqdn
        Parameters are either
            POST
            fqdn: str: fqdn
            years: array int: year to investigate
        or
            GET
            job_id: str request id

        Query Example:
        curl -X POST http://localhost:8000/get_uris_for_fqdn \
            -H 'Content-Type: application/json' -H 'Authorization: Bearer secret123' \
            -d '{
            "fqdn": "perdu.com",
            "years": [2024, 2025]
            }' -v


    ** All Uris for a given SHA1 ** 

    get_uris_for_hash, method POST : List of URIs for a given sha1 hash
        Parameters are either
            hash: str sha1 hash.
            years: array int: year to investigate
        or
            GET
            rid: str request id

        curl -X POST http://localhost:8000/get_uris_for_hash \
             -H 'Content-Type: application/json'   -H 'Authorization: Bearer secret123'   -d '{
             "hash": "8f18c62bab35a53013f7f087095e35eb187da5c4",
             "years": [2024, 2025]
            }' -v

    ** All unique(Uris) for a given Domain **

    get_fqdn_for_dom, method POST: List of URIs for a given domain
        Parameters are either
            dom: str domain.
            key: str API key.
            year: array int: year to investigate
        or
            rid: str request id
            key: str API key.

Tables are;

   ┌─name─────────┐
1. │ CCMAIN202547 │
2. │ YEAR2025     │
   └──────────────┘

Format is CCMAINYYYYID
ID start at 0 each Year.

Record is:
url_protocol:          http
url_host_name:         0ad594654.wotuodanle.com
url_path:              /
url_query:             dongyingk4jdkcl265893
content_digest:        AHSYGQOHPUZEYUXRR3BT3NB2ZG3N3CRZ
content_languages:     zho
content_mime_detected: text/html
warc_filename:         crawl-data/CC-MAIN-2025-47/segments/1762439342511.18/warc/CC-MAIN-20251107172614-20251107202614-00167.warc.gz
warc_record_offset:    2415
warc_record_length:    6540

"""

import logging
import base64
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import uuid
from pathlib import Path
from marshmallow import Schema, fields, validates_schema, ValidationError
import yaml
from flask import Flask, request, jsonify, abort
from clickhouse_driver import Client

app = Flask(__name__)
logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).with_name("config_cc4ail.yaml")
VERSION = 0


def load_config(path: Path) -> dict:
    """
    Load configuration for yaml file

    :param path: Description
    :type path: Path
    :return: None
    :rtype: dict[Any, Any]
    """

    try:
        with path.open("r", encoding="utf-8") as config_file:
            return yaml.safe_load(config_file) or {}
    except FileNotFoundError as exc:
        raise RuntimeError(f"Configuration file {path} not found.") from exc


try:
    CONFIG = load_config(CONFIG_PATH)
except yaml.YAMLError as exc:
    raise RuntimeError(
        f"Unable to parse configuration file {CONFIG_PATH}: {exc}"
    ) from exc

clickhouse_config = CONFIG.get("clickhouse") or {}

# --- Configuration ---
CLICKHOUSE_HOST = clickhouse_config.get("host", "localhost")
CLICKHOUSE_PORT = clickhouse_config.get("port", 9000)
CLICKHOUSE_USER = clickhouse_config.get("user", "default")
CLICKHOUSE_PASSWORD = clickhouse_config.get("password", "")
CLICKHOUSE_DB = clickhouse_config.get("database", "COMMON_CRAWL")

API_KEYS = CONFIG.get("api_keys")
if not isinstance(API_KEYS, list) or not API_KEYS:
    raise RuntimeError("Configuration must define a non-empty list under api_keys.")
API_KEYS = [str(key) for key in API_KEYS]

executor = ThreadPoolExecutor(max_workers=4)
jobs = (
    {}
)  # job_id -> {status [PENDING, RUNNING, ERROR, DONE], stage [0..100],  result , error}


def validate_years(years: list):
    """
    This function validate that year are a int list and in the range to 2015 - Now()

    :param years: Description
    :type years: list
    """

    # Check if array is empty
    if len(years) == 0:
        raise ValueError("Years parameter should be an integer array")

    # Check is at least 2015
    if all(ycurrent < 2014 for ycurrent in years):
        raise ValueError("No data for the requested years, It start in 2015")

    # Check is year is not > this year
    current_year = datetime.now().year
    if any(ycurrent > current_year for ycurrent in years):
        raise ValueError(f"Requested years cannot exceed {current_year}.")

    logger.debug("Years parameter successfully validated: %s", years)
    return


class GetUrisForFqdnSchema(Schema):
    """
    This class validate parameters for requestion Uris for a given domain.
    """

    fqdn = fields.String(required=False)
    job_id = fields.String(required=False)
    years = fields.List(fields.Integer(), required=False)

    @validates_schema
    def validate_identifier(self, data, **kwargs):
        """
        This function validate parameters

        :param self: Description
        :param data: Description
        :param kwargs: Description
        """
        has_fqdn = bool(data.get("fqdn"))
        has_job_id = bool(data.get("job_id"))
        years = data.get("years")
        if not has_fqdn and not has_job_id:
            raise ValidationError("Either fqdn or job_id must be provided.")
        if has_fqdn and has_job_id:
            raise ValidationError("Provide only one of fqdn or job_id.")

        if has_fqdn:
            if not years:
                raise ValidationError("Years must be provided when fqdn is supplied.")
            validate_years(years)
            fqdn_value = data["fqdn"]

            if not re.fullmatch(r"[a-z0-9._-]+", fqdn_value):
                raise ValidationError("fqdn seems invalid")


get_uris_for_fqdn_schema = GetUrisForFqdnSchema()


class GetUrisForHashSchema(Schema):
    """
    Validate parameters for retrieving URIs for a given SHA1 hash.
    """

    hash = fields.String(required=False)
    job_id = fields.String(required=False)
    years = fields.List(fields.Integer(), required=False)

    @validates_schema
    def validate_identifier(self, data, **kwargs):
        hash_value = data.get("hash")
        has_hash = bool(hash_value)
        has_job_id = bool(data.get("job_id"))
        years = data.get("years")
        if not has_hash and not has_job_id:
            raise ValidationError("Either hash or job_id must be provided.")
        if has_hash and has_job_id:
            raise ValidationError("Provide only one of hash or job_id.")

        if has_hash:
            if not years:
                raise ValidationError("Years must be provided when hash is supplied.")
            validate_years(years)
            hash_value = hash_value.lower()
            if not re.fullmatch(r"[0-9a-f]{40}", hash_value):
                raise ValidationError("Hash must be a 40-character hexadecimal SHA1.")


get_uris_for_hash_schema = GetUrisForHashSchema()


class GetFqdnsForDomSchema(Schema):
    """
    Validate parameters for retrieving FQDNs for a given domain.
    """

    domain = fields.String(required=False)
    job_id = fields.String(required=False)
    years = fields.List(fields.Integer(), required=False)

    @validates_schema
    def validate_identifier(self, data, **kwargs):
        domain_value = data.get("domain")
        has_domain = bool(domain_value)
        has_job_id = bool(data.get("job_id"))
        years = data.get("years")
        if not has_domain and not has_job_id:
            raise ValidationError("Either domain or job_id must be provided.")
        if has_domain and has_job_id:
            raise ValidationError("Provide only one of domain or job_id.")

        if has_domain:
            if not years:
                raise ValidationError("Years must be provided when domain is supplied.")
            validate_years(years)
            domain_value = domain_value.lower()

            if not re.fullmatch(r"[a-z0-9._-]+", domain_value):
                raise ValidationError("Invalid domain provided")


get_fqdns_for_dom_schema = GetFqdnsForDomSchema()


# --- Utilities ---
def get_client():
    return Client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        user=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DB,
    )


def get_all_ccmain_tables(client: Client, years: list) -> list[str]:

    tables = client.execute("SHOW TABLES")

    # Construct the rexeg to find tables.
    if len(years) == 1:
        ypattern = f"{years[0]}"
    else:
        years_str = [str(cyear) for cyear in years]
        ypattern = "|".join(years_str)
    ypattern = f"({ypattern})\\d+"
    logger.debug("Using CCMAIN table pattern: %s", ypattern)

    pattern = re.compile(r"CCMAIN" + ypattern)
    ccmain_tables = [t[0] for t in tables if pattern.fullmatch(t[0])]
    if not ccmain_tables:
        raise ValueError("No CCMAIN tables found in database")
    ccmain_tables.sort(key=lambda t: int(pattern.fullmatch(t).group(1)))
    # Now we limit to the
    logging.info("Found CCMAIN tables: %s", ccmain_tables)
    return ccmain_tables


def require_api_key():
    authorization_header = request.headers.get("Authorization")
    if not authorization_header or not authorization_header.startswith("Bearer "):
        abort(401)
    token = authorization_header.split(" ", 1)[1].strip()
    if token not in API_KEYS:
        abort(401)


def extract_timestamp(input_string: str) -> int | None:
    match = re.search(r"CC-MAIN-(\d{4})(\d{2})(\d{2})", input_string)
    if not match:
        return None
    year, month, day = match.groups()
    dt = datetime(int(year), int(month), int(day))
    return int(dt.timestamp())


def sha1_to_hex(base32_string: str) -> str:
    binary_data = base64.b32decode(base32_string)
    return binary_data.hex()


def sha1_hex_to_base32(hex_string: str) -> str:
    """
    Convert a hex-encoded SHA1 digest into the Base32 representation stored in ClickHouse.
    """

    binary_data = bytes.fromhex(hex_string)
    return base64.b32encode(binary_data).decode("ascii")


def sql_get_uris_for_fqdn(job_id: str):
    client = get_client()
    params = jobs[job_id]["params"]
    years = params.get("years")
    if not years:
        raise ValueError("Job parameters do not contain any years to query.")
    tables = get_all_ccmain_tables(client, years)

    step = 100 / len(tables)  # Step is the progression in %.
    logger.debug("tables lookup for %s", tables)

    fqdn = params["fqdn"]
    stage = 0

    urls = []
    for table_name in tables:
        sql = f"SELECT url_protocol, url_path, url_query, warc_filename, \
            content_digest FROM {table_name} WHERE url_host_name = %(fqdn)s"
        result = client.execute(sql, params={"fqdn": fqdn})

        # Conform response.
        if not isinstance(result, list):
            result = list(result or [])
        logger.debug(
            "Retrieved %d rows for fqdn %s table %s", len(result), fqdn, table_name
        )

        for line in result:
            scheme, path, query, filename, digest = line
            scheme = scheme or "https"
            path = path or "/"
            full_url = f"{scheme}://{fqdn}{path}"
            if query:
                full_url += "?" + query
            urls.append(
                {
                    "url": full_url,
                    "timestamp": extract_timestamp(filename),
                    "sha1": sha1_to_hex(digest),
                }
            )
        stage = stage + step
        jobs[job_id]["stage"] = stage  # Refresh the status.
    return urls


def sql_get_uris_for_hash(job_id: str):
    """
    This function for sql_get_uris_for_hash manague the query to the db
    for getting uris of a given hash.

    :param job_id: Description
    :type job_id: str
    """

    client = get_client()
    params = jobs[job_id]["params"]
    years = params.get("years")
    if not years:
        raise ValueError("Job parameters do not contain any years to query.")
    tables = get_all_ccmain_tables(client, years)

    step = 100 / len(tables)
    logger.debug("tables lookup for %s", tables)

    sha1_hex = params["hash"]
    digest = sha1_hex_to_base32(sha1_hex)
    stage = 0
    urls = []

    for table_name in tables:
        sql = (
            "SELECT url_protocol, url_host_name, url_path, url_query, "
            "warc_filename, content_digest "
            f"FROM {table_name} WHERE content_digest = %(digest)s"
        )
        result = client.execute(sql, params={"digest": digest})
        if not isinstance(result, list):
            result = list(result or [])
        logger.debug(
            "Retrieved %d rows for hash %s table %s", len(result), sha1_hex, table_name
        )

        stage = stage + step
        jobs[job_id]["stage"] = stage
        # if we had result, we build the URI and extract timestamp and sha1
        if result:
            for line in result:
                scheme, host, path, query, filename, digest_value = line
                scheme = scheme or "https"
                host = host or ""
                path = path or "/"
                full_url = f"{scheme}://{host}{path}"
                if query:
                    full_url += "?" + query
                urls.append(
                    {
                        "url": full_url,
                        "timestamp": extract_timestamp(filename),
                        "sha1": sha1_to_hex(digest_value),
                    }
                )

    return urls


def sql_get_fqdns_for_dom(job_id: str):
    """
    This function for sql_get_fqdns_for_hash manage the query to the db
    for getting uris of a given hash.

    :param job_id: Description
    :type job_id: str
    """

    client = get_client()
    params = jobs[job_id]["params"]
    years = params.get("years")
    if not years:
        raise ValueError("Job parameters do not contain any years to query.")
    tables = get_all_ccmain_tables(client, years)

    step = 100 / len(tables)
    logger.debug("tables lookup for %s", tables)

    domain = params["domain"]
    stage = 0

    fqdns = []

    for table_name in tables:

        sql = (
            "SELECT distinct(url_host_name) "
            f"FROM {table_name} WHERE url_host_name like %(dom)s"
        )

        if domain.startswith("."):  # Ensure we ask for a domain
            domain = domain[1::]

        result = client.execute(sql, params={"dom": "%." + domain})
        if not isinstance(result, list):
            result = list(result or [])
        logger.debug(
            "Retrieved %d rows for hash %s table %s", len(result), domain, table_name
        )

        stage = stage + step
        jobs[job_id]["stage"] = stage
        # if we had result, we build the URI and extract timestamp and sha1
        if result:
            for line in result:
                fqdns.append(line[0])
    return list(set(fqdns))


def task_uris_for_fqdn(job_id):  # , request_payload):
    logger.info("Job %s started", job_id)
    jobs[job_id]["status"] = "RUNNING"
    try:
        results = sql_get_uris_for_fqdn(job_id)
        jobs[job_id]["status"] = "DONE"
        jobs[job_id]["result"] = results
        logger.info("Job %s completed", job_id)
    except Exception as exception:
        jobs[job_id]["status"] = "ERROR"
        jobs[job_id]["error"] = str(exception)
        logger.exception("Job %s failed: %s", job_id, exception)


def task_uris_for_hash(job_id):  # , request_payload):
    logger.info("Hash job %s started", job_id)
    jobs[job_id]["status"] = "RUNNING"
    try:
        results = sql_get_uris_for_hash(job_id)
        jobs[job_id]["status"] = "DONE"
        jobs[job_id]["result"] = results
        logger.info("Hash job %s completed", job_id)
    except Exception as exception:
        jobs[job_id]["status"] = "ERROR"
        jobs[job_id]["error"] = str(exception)
        logger.exception("Hash job %s failed: %s", job_id, exception)


def task_fqdns_for_dom(job_id):
    logger.info("Dom job %s started", job_id)
    jobs[job_id]["status"] = "RUNNING"
    try:
        results = sql_get_fqdns_for_dom(job_id)
        jobs[job_id]["status"] = "DONE"
        jobs[job_id]["result"] = results
        logger.info("Dom job %s completed", job_id)
    except Exception as exception:
        jobs[job_id]["status"] = "ERROR"
        jobs[job_id]["error"] = str(exception)
        logger.exception("Dom job %s failed: %s", job_id, exception)


#### Job Creation Route


@app.post("/get_uris_for_fqdn")
def create_job():
    require_api_key()

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Invalid or missing JSON body"}), 400
    try:
        # Load the params and validate them.
        logger.debug("Received payload for job creation: %s", payload)
        params = get_uris_for_fqdn_schema.load(payload)
    except ValidationError as err:
        logger.warning("Payload validation error: %s", err)
        return jsonify({"error": err.messages}), 400

    logger.info("Validated get_uris_for_fqdn parameters: %s", params)
    # return jsonify({"status": "parameters received"})

    # request_payload = request.json or {}
    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "status": "PENDING",
        "stage": 0,
        "result": None,
        "error": None,
        "params": params,
    }
    executor.submit(task_uris_for_fqdn, job_id)  # , request_payload)
    return jsonify({"job_id": job_id}), 202


@app.post("/get_uris_for_hash")
def create_hash_job():
    require_api_key()

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Invalid or missing JSON body"}), 400
    try:
        logger.debug("Received payload for hash job creation: %s", payload)
        params = get_uris_for_hash_schema.load(payload)
    except ValidationError as err:
        logger.warning("Hash payload validation error: %s", err)
        return jsonify({"error": err.messages}), 400

    logger.info("Validated get_uris_for_hash parameters: %s", params)
    # request_payload = request.json or {}
    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "status": "PENDING",
        "stage": 0,
        "result": None,
        "error": None,
        "params": params,
    }
    executor.submit(task_uris_for_hash, job_id)  # , request_payload)
    return jsonify({"job_id": job_id}), 202


@app.post("/get_fqdns_for_dom")
def create_dom_job():
    require_api_key()

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Invalid or missing JSON body"}), 400
    try:
        logger.debug("Received payload for hash job creation: %s", payload)
        params = get_fqdns_for_dom_schema.load(payload)
    except ValidationError as err:
        logger.warning("Payload validation error: %s", err)
        return jsonify({"error": err.messages}), 400

    logger.info("Validated get_uris_for_hash parameters: %s", params)
    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "status": "PENDING",
        "stage": 0,
        "result": None,
        "error": None,
        "params": params,
    }
    executor.submit(task_fqdns_for_dom, job_id)  # , request_payload)
    return jsonify({"job_id": job_id}), 202


#### Job Status Route
@app.get("/version")
def get_version():
    """
    This webpage act as SLB HeartBeat
    It validate fully access and queriable status to the DB
    """
    try:
        client = get_client()
        # Get current year
        years = list(range(2015, datetime.now().year + 1))
        tables = get_all_ccmain_tables(client, years)
        for table_name in tables:
            sql = "SELECT distinct(url_host_name) " f"FROM {table_name} limit 1"
            result = client.execute(sql)
            if not isinstance(result, list):
                result = list(result or [])
            if len(result) == 1:
                return jsonify({"status": "up", "version": VERSION})
        return jsonify({"status": "down", "version": VERSION})
    except:
        return jsonify({"status": "down", "version": VERSION})


@app.get("/get_uris_for_fqnd/<job_id>")
@app.get("/get_uris_for_hash/<job_id>")
@app.get("/get_fqdns_for_dom/<job_id>")
def get_job(job_id):
    """
    This function receive job status query and also send the result.
    """
    require_api_key()
    job = jobs.get(job_id)
    if job is None:
        return jsonify({"error": "job not found"}), 404

    # Still Running
    if job["status"] in ("PENDING", "RUNNING"):
        return jsonify({"status": job["status"], "stage": job["stage"]}), 202

    # ... Well.. Dead.. Cleanit after.
    if job["status"] == "ERROR":
        response = jsonify({"status": "ERROR", "error": job["error"]})
        jobs.pop(job_id, None)
        return response, 500

    # Ready, send result and clean it.
    if job["status"] == "DONE":
        response_payload = {"status": "DONE", "stage": "100", "result": job["result"]}
        response = jsonify(response_payload)
        jobs.pop(job_id, None)
        return response, 200
    return jsonify({"error": "unexpected status"}), 500


# --- Main ---
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="::", port=8000)
