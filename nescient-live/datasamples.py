resampled = {
    "took": 23,
    "timed_out": False,
    "_shards": {
        "total": 1,
        "successful": 1,
        "skipped": 0,
        "failed": 0
    },
    "hits": {
        "total": {
            "value": 10000,
            "relation": "gte"
        },
        "max_score": None,
        "hits": []
    },
    "aggregations": {
        "all_attributes": {
            "buckets": [
                {
                    "key_as_string": "2021-03-14T14:23:45.000Z",
                    "key": 1615731825000,
                    "doc_count": 1,
                    "UDIP": {
                        "value": 1
                    },
                    "USIP": {
                        "value": 1
                    },
                    "UPR": {
                        "value": 1
                    },
                    "packets": {
                        "value": 5.0
                    }
                },
                {
                    "key_as_string": "2021-03-14T14:23:48.000Z",
                    "key": 1615731828000,
                    "doc_count": 3,
                    "UDIP": {
                        "value": 1
                    },
                    "USIP": {
                        "value": 3
                    },
                    "UPR": {
                        "value": 1
                    },
                    "packets": {
                        "value": 15.0
                    }
                }
            ]
        }
    }
}

aggregated = {
    "took": 2,
    "timed_out": False,
    "_shards": {
        "total": 1,
        "successful": 1,
        "skipped": 0,
        "failed": 0
    },
    "hits": {
        "total": {
            "value": 2944,
            "relation": "eq"
        },
        "max_score": None,
        "hits": []
    },
    "aggregations": {
        "UDIP": {
            "value": 1
        },
        "USIP": {
            "value": 3
        },
        "UPR": {
            "value": 1
        },
        "packets": {
            "value": 270.0
        }
    }
}

single_data = {
    "took": 2,
    "timed_out": False,
    "_shards": {
        "total": 1,
        "successful": 1,
        "skipped": 0,
        "failed": 0
    },
    "hits": {
        "total": {
            "value": 2,
            "relation": "eq"
        },
        "max_score": 1.0,
        "hits": [
            {
                "_index": "filebeat-7.11.2-2021.03.14-000001",
                "_type": "_doc",
                "_id": "3DQUMXgBZgHJMCwYTZ9l",
                "_score": 1.0,
                "_source": {
                    "netflow": {
                        "destination_ipv4_address": "10.0.0.2",
                        "protocol_identifier": 6,
                        "source_ipv4_address": "10.0.1.4",
                        "destination_transport_port": 80
                    }
                }
            }
        ]
    }
}
