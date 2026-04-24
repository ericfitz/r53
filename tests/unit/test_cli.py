"""End-to-end tests for r53.main(argv, clients) with injected stubbed clients."""

import pytest

from r53 import Clients, main


def _zones_response(zones):
    return {
        "HostedZones": [
            {
                "Id": f"/hostedzone/{zid}",
                "Name": f"{name}.",
                "CallerReference": "x",
                "Config": {"PrivateZone": False},
            }
            for zid, name in zones
        ],
        "Marker": "",
        "IsTruncated": False,
        "MaxItems": "100",
    }


def _rrsets_response(rrsets):
    return {"ResourceRecordSets": rrsets, "IsTruncated": False, "MaxItems": "100"}


def test_main_listzones(stubbed_route53, stubbed_ec2, capsys):
    r53_client, r53_stubber = stubbed_route53
    ec2_client, _ = stubbed_ec2
    r53_stubber.add_response(
        "list_hosted_zones",
        _zones_response([("Z1", "example.com"), ("Z2", "other.com")]),
    )

    main(argv=[], clients=Clients(route53=r53_client, ec2=ec2_client))
    captured = capsys.readouterr()
    assert "Z1 example.com" in captured.out
    assert "Z2 other.com" in captured.out


def test_main_list_in_zone(stubbed_route53, stubbed_ec2, capsys):
    r53_client, r53_stubber = stubbed_route53
    ec2_client, _ = stubbed_ec2
    r53_stubber.add_response(
        "list_hosted_zones", _zones_response([("Z1", "example.com")])
    )
    r53_stubber.add_response(
        "list_resource_record_sets",
        _rrsets_response(
            [
                {
                    "Name": "foo.example.com.",
                    "Type": "A",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": "1.2.3.4"}],
                }
            ]
        ),
        expected_params={"HostedZoneId": "Z1", "StartRecordName": "."},
    )

    main(
        argv=["--zone", "example.com"],
        clients=Clients(route53=r53_client, ec2=ec2_client),
    )
    captured = capsys.readouterr()
    assert "Name: foo.example.com" in captured.out


def test_main_describe_record(stubbed_route53, stubbed_ec2, capsys):
    r53_client, r53_stubber = stubbed_route53
    ec2_client, _ = stubbed_ec2
    r53_stubber.add_response(
        "list_hosted_zones", _zones_response([("Z1", "example.com")])
    )
    r53_stubber.add_response(
        "list_resource_record_sets",
        _rrsets_response(
            [
                {
                    "Name": "foo.example.com.",
                    "Type": "A",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": "1.2.3.4"}],
                }
            ]
        ),
        expected_params={
            "HostedZoneId": "Z1",
            "StartRecordName": "foo.example.com",
        },
    )

    main(
        argv=["--zone", "example.com", "--name", "foo"],
        clients=Clients(route53=r53_client, ec2=ec2_client),
    )
    captured = capsys.readouterr()
    assert "Name: foo.example.com" in captured.out
    assert "Value: 1.2.3.4" in captured.out


def test_main_upsert_explicit_type(stubbed_route53, stubbed_ec2):
    r53_client, r53_stubber = stubbed_route53
    ec2_client, _ = stubbed_ec2
    r53_stubber.add_response(
        "list_hosted_zones", _zones_response([("Z1", "example.com")])
    )
    r53_stubber.add_response(
        "change_resource_record_sets",
        {
            "ChangeInfo": {
                "Id": "/change/C1",
                "Status": "PENDING",
                "SubmittedAt": __import__("datetime").datetime(2026, 1, 1),
            }
        },
        expected_params={
            "HostedZoneId": "Z1",
            "ChangeBatch": {
                "Comment": "r53.py",
                "Changes": [
                    {
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": "foo.example.com",
                            "Type": "A",
                            "TTL": 300,
                            "ResourceRecords": [{"Value": "1.2.3.4"}],
                        },
                    }
                ],
            },
        },
    )

    main(
        argv=[
            "--zone", "example.com",
            "--name", "foo",
            "--type", "A",
            "--value", "1.2.3.4",
        ],
        clients=Clients(route53=r53_client, ec2=ec2_client),
    )


def test_main_delete_reads_then_deletes(stubbed_route53, stubbed_ec2):
    r53_client, r53_stubber = stubbed_route53
    ec2_client, _ = stubbed_ec2
    r53_stubber.add_response(
        "list_hosted_zones", _zones_response([("Z1", "example.com")])
    )
    # Second call: get_current_record reads the record
    r53_stubber.add_response(
        "list_resource_record_sets",
        _rrsets_response(
            [
                {
                    "Name": "foo.example.com.",
                    "Type": "A",
                    "TTL": 600,
                    "ResourceRecords": [{"Value": "9.9.9.9"}],
                }
            ]
        ),
        expected_params={
            "HostedZoneId": "Z1",
            "StartRecordName": "foo.example.com",
        },
    )
    # Third call: the DELETE change batch built from the read-back
    r53_stubber.add_response(
        "change_resource_record_sets",
        {
            "ChangeInfo": {
                "Id": "/change/C2",
                "Status": "PENDING",
                "SubmittedAt": __import__("datetime").datetime(2026, 1, 1),
            }
        },
        expected_params={
            "HostedZoneId": "Z1",
            "ChangeBatch": {
                "Comment": "r53.py",
                "Changes": [
                    {
                        "Action": "DELETE",
                        "ResourceRecordSet": {
                            "Name": "foo.example.com",
                            "Type": "A",
                            "TTL": 600,
                            "ResourceRecords": [{"Value": "9.9.9.9"}],
                        },
                    }
                ],
            },
        },
    )

    main(
        argv=[
            "--zone", "example.com",
            "--name", "foo",
            "--type", "A",
            "--delete",
        ],
        clients=Clients(route53=r53_client, ec2=ec2_client),
    )


def test_main_invalid_ttl(stubbed_route53, stubbed_ec2):
    r53_client, _ = stubbed_route53
    ec2_client, _ = stubbed_ec2
    with pytest.raises(ValueError, match="TTL must be between"):
        main(
            argv=["--ttl", "-1"],
            clients=Clients(route53=r53_client, ec2=ec2_client),
        )


def test_main_two_value_sources(stubbed_route53, stubbed_ec2):
    r53_client, _ = stubbed_route53
    ec2_client, _ = stubbed_ec2
    with pytest.raises(ValueError, match="Specify only one of"):
        main(
            argv=[
                "--zone", "example.com",
                "--name", "foo",
                "--value", "1.2.3.4",
                "--myip",
            ],
            clients=Clients(route53=r53_client, ec2=ec2_client),
        )


def test_main_unknown_zone(stubbed_route53, stubbed_ec2):
    r53_client, r53_stubber = stubbed_route53
    ec2_client, _ = stubbed_ec2
    r53_stubber.add_response(
        "list_hosted_zones", _zones_response([("Z1", "other.com")])
    )

    with pytest.raises(ValueError, match="not found in Route 53"):
        main(
            argv=["--zone", "missing.example.com"],
            clients=Clients(route53=r53_client, ec2=ec2_client),
        )


def test_main_delete_nonexistent(stubbed_route53, stubbed_ec2):
    r53_client, r53_stubber = stubbed_route53
    ec2_client, _ = stubbed_ec2
    r53_stubber.add_response(
        "list_hosted_zones", _zones_response([("Z1", "example.com")])
    )
    # Return no matching record
    r53_stubber.add_response(
        "list_resource_record_sets",
        _rrsets_response([]),
        expected_params={
            "HostedZoneId": "Z1",
            "StartRecordName": "foo.example.com",
        },
    )

    with pytest.raises(ValueError, match="Cannot delete nonexistent"):
        main(
            argv=[
                "--zone", "example.com",
                "--name", "foo",
                "--type", "A",
                "--delete",
            ],
            clients=Clients(route53=r53_client, ec2=ec2_client),
        )
