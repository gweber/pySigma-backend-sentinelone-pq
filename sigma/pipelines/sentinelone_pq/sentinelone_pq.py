from sigma.processing.conditions import LogsourceCondition
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation, ChangeLogsourceTransformation, HashesFieldsDetectionItemTransformation, CaseTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition, RuleContainsFieldCondition, IsSigmaRuleCondition
from sigma.processing.condition_expressions import parse_condition_expression
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.rule import SigmaDetectionItem
from sigma.exceptions import SigmaTransformationError

class InvalidFieldTransformation(DetectionItemFailureTransformation):
    """
    Overrides the apply_detection_item() method from DetectionItemFailureTransformation to also include the field name
    in the error message
    """

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        field_name = detection_item.field
        self.message = f"Invalid SigmaDetectionItem field name encountered: {field_name}. " + self.message
        raise SigmaTransformationError(self.message)

def sentinelonepq_pipeline() -> ProcessingPipeline:

    general_supported_fields = [
        'event.category',
        'event.type'
    ]

    # Sigma's Hashes field ("SHA256=..., MD5=...") is split into one field per algorithm by pySigma's own
    # transformation, for the categories whose events carry the hashes.
    hash_fields = ['Hashes', 'Hash']

    # The machine an event happened on: every Deep Visibility event carries endpoint.name, whatever its category.
    host_fields = {"ComputerName": "endpoint.name"}

    translation_dict = {
        'process_creation':{
            "ProcessId":"tgt.process.pid",
            "Image":"tgt.process.image.path",
            "Description":"tgt.process.displayName", #Not sure whether this should be Description or Product???
            "Publisher": "tgt.process.publisher",
            "Product":"tgt.process.displayName",
            "Company":"tgt.process.publisher",
            "CommandLine":"tgt.process.cmdline",
            "CurrentDirectory":"tgt.process.image.path",
            "User":"tgt.process.user",
            "TerminalSessionId":"tgt.process.sessionid",
            "IntegrityLevel":"tgt.process.integrityLevel",
            "md5":"tgt.process.image.md5",
            "sha1":"tgt.process.image.sha1",
            "sha256":"tgt.process.image.sha256",
            "MD5":"tgt.process.image.md5",
            "SHA1":"tgt.process.image.sha1",
            "SHA256":"tgt.process.image.sha256",
            "ParentProcessId":"src.process.pid",
            "ParentImage":"src.process.image.path",
            "ParentCommandLine":"src.process.cmdline",
        },
        'file':{
            "Image": "src.process.image.path",
            "CommandLine":"src.process.cmdline",
            "ParentImage":"src.process.parent.image.path",
            "ParentCommandLine":"src.process.parent.cmdline",
            "TargetFilename":"tgt.file.path", 
            "SourceFilename":"tgt.file.oldPath",
            "User":"src.process.user"
        },
        'image_load':{
            "ImageLoaded":"module.path",
            "Image": "src.process.image.path",
            "CommandLine":"src.process.cmdline",
            "ParentImage":"src.process.parent.image.path",
            "ParentCommandLine":"src.process.parent.cmdline",
            "sha1":"module.sha1",
            "md5": "module.md5",
            "SHA1":"module.sha1",
            "MD5": "module.md5"
        },
        'pipe_creation':{
            "PipeName":"namedPipe.name",
            "Image": "src.process.image.path",
            "CommandLine":"src.process.cmdline",
            "ParentImage":"src.process.parent.image.path",
            "ParentCommandLine":"src.process.parent.cmdline",
        },
        'registry':{
            "Image": "src.process.image.path",
            "CommandLine":"src.process.cmdline",
            "ParentImage":"src.process.parent.image.path",
            "ParentCommandLine":"src.process.parent.cmdline",
            "TargetObject": "registry.keyPath",
            "Details": "registry.value"
        },
        'dns':{
            "Image": "src.process.image.path",
            "CommandLine":"src.process.cmdline",
            "ParentImage":"src.process.parent.image.path",
            "ParentCommandLine":"src.process.parent.cmdline",
            "query": "event.dns.request",
            "answer":"event.dns.response",
            "QueryName": "event.dns.request",
            "record_type":"event.dns.response"
        },
        'network':{
            "Image": "src.process.image.path",
            "CommandLine":"src.process.cmdline",
            "ParentImage":"src.process.parent.image.path",
            "ParentCommandLine":"src.process.parent.cmdline",
            "DestinationHostname":["url.address", "event.dns.request"],
            "DestinationPort":"dst.port.number",
            "DestinationIp":"dst.ip.address",
            "User":"src.process.user",
            "SourceIp":"src.ip.address",
            "SourcePort":"src.port.number",
            "Protocol":"NetProtocolName",
            "dst_ip":"dst.ip.address",
            "src_ip":"src.ip.address",
            "dst_port":"dst.port.number",
            "src_port":"src.port.number"
        }
    }

    for category in translation_dict.values():
        category.update(host_fields)

    os_filter = [
        # Add EndpointOS = Linux
        ProcessingItem(
            identifier="s1_pq_linux_product",
            transformation=AddConditionTransformation({
                "endpoint.os": "linux"
            }),
            rule_conditions=[
                LogsourceCondition(product="linux")
            ]
        ),
        # Add EndpointOS = Windows
        ProcessingItem(
            identifier="s1_pq_windows_product",
            transformation=AddConditionTransformation({
                "endpoint.os": "windows"
            }),
            rule_conditions=[
                LogsourceCondition(product="windows")
            ]
        ),
        # Add EndpointOS = OSX
        ProcessingItem(
            identifier="s1_pq_osx_product",
            transformation=AddConditionTransformation({
                "endpoint.os":"osx"
            }),
            rule_conditions=[
                LogsourceCondition(product="macos")
            ]
        )
    ]

    object_event_type_filter = [
        # Add EventType = Process Creation
        ProcessingItem(
            identifier="s1_pq_process_creation_eventtype",
            transformation=AddConditionTransformation({
                "event.type": "Process Creation"
            }),
            rule_conditions=[
                LogsourceCondition(category="process_creation")
            ]
        ),
        # Add EventType = "File Creation": Sigma's file_event is a file created (Sysmon event 11). The
        # category "file" also held File Deletion, Rename, Modification and Scan events.
        ProcessingItem(
            identifier="s1_pq_file_event_objecttype",
            transformation=AddConditionTransformation({
                "event.type": "File Creation"
            }),
            rule_conditions=[
                LogsourceCondition(category="file_event")
            ]
        ),
        # Add EventType = "File Modification"
        ProcessingItem(
            identifier="s1_pq_file_change_eventtype",
            transformation=AddConditionTransformation({
                "event.type": "File Modification"
            }),
            rule_conditions=[
                LogsourceCondition(category="file_change")
            ]
        ),
        # Add EventType = "File Rename"
        ProcessingItem(
            identifier="s1_pq_file_rename_eventtype",
            transformation=AddConditionTransformation({
                "event.type": "File Rename"
            }),
            rule_conditions=[
                LogsourceCondition(category="file_rename")
            ]
        ),
        # Add EventType = "File Deletion" (SentinelOne's name; "File Delete" matched no event)
        ProcessingItem(
            identifier="s1_pq_file_delete_eventtype",
            transformation=AddConditionTransformation({
                "event.type": "File Deletion"
            }),
            rule_conditions=[
                LogsourceCondition(category="file_delete")
            ]
        ),
        # Add EventType = "Module Load"
        ProcessingItem(
            identifier="s1_pq_image_load_eventtype",
            transformation=AddConditionTransformation({
                "event.type": "Module Load"
            }),
            rule_conditions=[
                LogsourceCondition(category="image_load")
            ]
        ),
        # Add EventType for Pipe Creation
        ProcessingItem(
            identifier="s1_pq_pipe_creation_eventtype",
            transformation=AddConditionTransformation({
                "event.type": "Named Pipe Creation"
            }),
            rule_conditions=[
                LogsourceCondition(category="pipe_creation")
            ]
        ),
        # Registry: each Sigma category as the SentinelOne event types it means (Sysmon events 12-14).
        # registry_event is any of them; registry_add a key created, registry_delete a key or value
        # deleted, registry_set a value set (created or modified).
        ProcessingItem(
            identifier="s1_pq_registry_eventtype",
            transformation=AddConditionTransformation({
                "event.category": "registry"
            }),
            rule_conditions=[
                LogsourceCondition(category="registry_event")
            ]
        ),
        ProcessingItem(
            identifier="s1_pq_registry_add_eventtype",
            transformation=AddConditionTransformation({
                "event.type": "Registry Key Create"
            }),
            rule_conditions=[
                LogsourceCondition(category="registry_add")
            ]
        ),
        ProcessingItem(
            identifier="s1_pq_registry_delete_eventtype",
            transformation=AddConditionTransformation({
                "event.type": ["Registry Key Delete", "Registry Value Delete"]
            }),
            rule_conditions=[
                LogsourceCondition(category="registry_delete")
            ]
        ),
        ProcessingItem(
            identifier="s1_pq_registry_set_eventtype",
            transformation=AddConditionTransformation({
                "event.type": ["Registry Value Create", "Registry Value Modified"]
            }),
            rule_conditions=[
                LogsourceCondition(category="registry_set")
            ]
        ),
        # Add ObjectType for DNS Stuff
        ProcessingItem(
            identifier="s1_pq_dns_objecttype",
            transformation=AddConditionTransformation({
                "event.category":"dns"
            }),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="dns_query"),
                LogsourceCondition(category="dns")
            ]
        ),
        # Network connections are the "ip" events (IP Connect, IP Listen). The dns and url events also
        # carry processes and some a destination address (the resolver), so a rule on the process alone
        # matched every DNS lookup and web request it made. Only a rule on DestinationHostname, which
        # SentinelOne keeps on dns and url events, reads those as well.
        ProcessingItem(
            identifier="s1_pq_network_objecttype",
            transformation=AddConditionTransformation({
                "event.category": "ip"
            }),
            rule_conditions={
                "net": LogsourceCondition(category="network_connection"),
                "host": RuleContainsFieldCondition(field="DestinationHostname"),
            },
            rule_condition_expression=parse_condition_expression("net and not host")
        ),
        ProcessingItem(
            identifier="s1_pq_network_hostname_objecttype",
            transformation=AddConditionTransformation({
                "event.category": ["dns","url","ip"]
            }),
            rule_conditions={
                "net": LogsourceCondition(category="network_connection"),
                "host": RuleContainsFieldCondition(field="DestinationHostname"),
            },
            rule_condition_expression=parse_condition_expression("net and host")
        )
    ]

    field_mappings = [
        # Process Creation
        ProcessingItem(
            identifier="s1_pq_process_creation_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['process_creation']),
            rule_conditions=[
                LogsourceCondition(category="process_creation")
            ]
        ),
        # File Stuff
        ProcessingItem(
            identifier="s1_pq_file_change_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['file']),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event")
            ]
        ),
        # Module Load Stuff
        ProcessingItem(
            identifier="s1_pq_image_load_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['image_load']),
            rule_conditions=[
                LogsourceCondition(category="image_load")
            ]
        ),
        # Pipe Creation Stuff
        ProcessingItem(
            identifier="s1_pq_pipe_creation_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['pipe_creation']),
            rule_conditions=[
                LogsourceCondition(category="pipe_creation")
            ]
        ),
        # Registry Stuff
        ProcessingItem(
            identifier="s1_pq_registry_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['registry']),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set")
            ]
        ),
        # DNS Stuff
        ProcessingItem(
            identifier="s1_pq_dns_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['dns']),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="dns_query"),
                LogsourceCondition(category="dns")
            ]
        ),
        # Network Stuff
        ProcessingItem(
            identifier="s1_pq_network_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['network']),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall")
            ]
        )
    ]

    hashes = [
        ProcessingItem(
            identifier="s1_pq_process_creation_hashes",
            transformation=HashesFieldsDetectionItemTransformation(valid_hash_algos=["MD5", "SHA1", "SHA256"]),
            rule_conditions=[
                LogsourceCondition(category="process_creation")
            ]
        ),
        ProcessingItem(
            identifier="s1_pq_image_load_hashes",
            transformation=HashesFieldsDetectionItemTransformation(valid_hash_algos=["MD5", "SHA1"]),
            rule_conditions=[
                LogsourceCondition(category="image_load")
            ]
        ),
        # Hashes left over: a category whose events carry no hashes in SentinelOne.
        ProcessingItem(
            identifier="s1_pq_fail_hashes_not_supported",
            transformation=InvalidFieldTransformation("Hashes are supported for process_creation (MD5, SHA1, SHA256) "
                                                      "and image_load (MD5, SHA1)."),
            field_name_conditions=[
                IncludeFieldCondition(fields=hash_fields)
            ]
        ),
        # SentinelOne stores hashes in lower case and compares them case-sensitively: an upper-case
        # hash, as Sigma rules often write them, would match nothing.
        ProcessingItem(
            identifier="s1_pq_hashes_lowercase",
            transformation=CaseTransformation(method="lower"),
            field_name_conditions=[
                IncludeFieldCondition(fields=["md5", "sha1", "sha256", "MD5", "SHA1", "SHA256"])
            ]
        ),
    ]

    change_logsource_info = [
        # Marks a rule whose log source the pipeline maps (s1_pq_fail_rule_not_supported asks for it). A marker
        # only: replacing the log source with service "sentinelone" also blanked its category and product, so a
        # correlation rule converted after the rules it refers to found no category and kept its group-by
        # fields unmapped (Image instead of src.process.image.path).
        ProcessingItem(
            identifier="s1_pq_logsource",
            transformation=SetStateTransformation("s1_pq_logsource_mapped", True),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="process_creation"),
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event"),
                LogsourceCondition(category="image_load"),
                LogsourceCondition(category="pipe_creation"),
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set"),
                LogsourceCondition(category="dns"),
                LogsourceCondition(category="dns_query"),
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall")
            ]
        ),
    ]

    unsupported_rule_types = [
        # Show error if unsupported option
        # A detection rule whose log source the pipeline does not map. A correlation rule has no log source of
        # its own (it refers to detection rules), so it is not one of these.
        ProcessingItem(
            identifier="s1_pq_fail_rule_not_supported",
            transformation=RuleFailureTransformation("Rule type not yet supported by the SentinelOne PQ Sigma backend"),
            rule_conditions={
                "detection": IsSigmaRuleCondition(),
                "mapped": RuleProcessingItemAppliedCondition("s1_pq_logsource"),
            },
            rule_condition_expression=parse_condition_expression("detection and not mapped")
        )
    ]

    # Which fields a rule may use is decided per log source category: a field another category maps (User
    # for a process, on a DNS rule) passed a check against all of them together and reached the query unmapped,
    # as a field Deep Visibility does not have, which it answers with no event rather than an error.
    category_groups = {
        "process_creation": ["process_creation"],
        "file": ["file_change", "file_rename", "file_delete", "file_event"],
        "image_load": ["image_load"],
        "pipe_creation": ["pipe_creation"],
        "registry": ["registry_add", "registry_delete", "registry_event", "registry_set"],
        "dns": ["dns_query", "dns"],
        "network": ["network_connection", "firewall"],
    }
    unsupported_field_name = [
        ProcessingItem(
            identifier=f"s1_pq_fail_field_not_supported_{group}",
            transformation=InvalidFieldTransformation(f"This pipeline supports the following fields for {group}:\n{{"
                                                      + "}, {".join(sorted(translation_dict[group])) + "}"),
            field_name_conditions=[
                ExcludeFieldCondition(fields=list(translation_dict[group]) + general_supported_fields + hash_fields)
            ],
            rule_condition_linking=any,
            rule_conditions=[LogsourceCondition(category=c) for c in categories],
        )
        for group, categories in category_groups.items()
    ]

    return ProcessingPipeline(
        name="SentinelOne PQ pipeline",
        priority=50,
        items = [
            *unsupported_field_name,
            *os_filter,
            *object_event_type_filter,
            *hashes,
            *field_mappings,
            *change_logsource_info,
            *unsupported_rule_types,
        ]
    )