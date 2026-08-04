"""Source fragment injected into the sandbox as ``redteam_sdk.GrpcClient``."""

GRPC_SDK_SOURCE = r'''

class CapabilityUnavailableError(RuntimeError):
    pass


class GrpcResponse:
    """Structured gRPC result consumed by Executor and Evaluator."""

    def __init__(self, ok, service, method, payload=None, code="OK", details="", metadata=None):
        self.ok = bool(ok)
        self.service = service
        self.method = method
        self.payload = payload
        self.code = code
        self.details = details
        self.metadata = metadata or {}

    def to_dict(self):
        return {
            "protocol": "grpc",
            "ok": self.ok,
            "service": self.service,
            "method": self.method,
            "payload": self.payload,
            "code": self.code,
            "details": self.details,
            "metadata": self.metadata,
        }


def _grpc_runtime_target(target):
    requested = str(target or "").strip()
    requested_authority = requested.split("://", 1)[-1].rstrip("/")
    for path in (_CONTEXT_PATH, f"{_WORKSPACE}/context.json"):
        try:
            target_context = json.loads(Path(path).read_text()).get("target_context", {})
        except (OSError, json.JSONDecodeError):
            continue
        for item in target_context.get("runtime_targets", []):
            logical = item.get("logical", {})
            runtime = item.get("runtime", {})
            if str(logical.get("protocol", "")).lower() != "grpc":
                continue
            logical_authority = f"{logical.get('host', '')}:{logical.get('port', '')}".strip(":")
            if requested_authority and logical_authority and requested_authority != logical_authority:
                continue
            host = runtime.get("host")
            port = runtime.get("port")
            if host and port:
                return f"{host}:{port}"
    return requested_authority


class GrpcClient:
    """Reflection-backed unary gRPC client with dict protobuf payloads."""

    @staticmethod
    def call(target, service, method, payload, metadata=None):
        if not isinstance(payload, dict):
            raise TypeError("GrpcClient.call payload must be a structured object")
        if metadata is not None and not isinstance(metadata, dict):
            raise TypeError("GrpcClient.call metadata must be an object")
        try:
            import grpc
            from google.protobuf import descriptor_pool, descriptor_pb2, json_format, message_factory
            from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc
        except ImportError as exc:
            raise CapabilityUnavailableError(
                "grpc_client requires grpcio, protobuf, and grpcio-reflection"
            ) from exc

        authority = _grpc_runtime_target(target)
        if not authority:
            raise ValueError("GrpcClient.call target is required")
        secure = str(target).startswith("grpcs://")
        channel = (
            grpc.secure_channel(authority, grpc.ssl_channel_credentials())
            if secure else grpc.insecure_channel(authority)
        )
        rpc_path = f"/{service}/{method}"
        try:
            reflection = reflection_pb2_grpc.ServerReflectionStub(channel)
            request = reflection_pb2.ServerReflectionRequest(
                file_containing_symbol=service
            )
            response = next(reflection.ServerReflectionInfo(iter((request,))))
            if response.HasField("error_response"):
                raise RuntimeError(
                    f"gRPC reflection failed: {response.error_response.error_message}"
                )
            serialized_files = list(
                response.file_descriptor_response.file_descriptor_proto
            )
            pool = descriptor_pool.DescriptorPool()
            pending = list(serialized_files)
            while pending:
                deferred = []
                for serialized in pending:
                    try:
                        pool.AddSerializedFile(serialized)
                    except Exception:
                        deferred.append(serialized)
                if len(deferred) == len(pending):
                    raise RuntimeError("gRPC reflection returned unresolved descriptors")
                pending = deferred

            service_descriptor = pool.FindServiceByName(service)
            method_descriptor = service_descriptor.FindMethodByName(method)
            request_class = message_factory.GetMessageClass(
                method_descriptor.input_type
            )
            response_class = message_factory.GetMessageClass(
                method_descriptor.output_type
            )
            request_message = json_format.ParseDict(
                payload, request_class(), ignore_unknown_fields=False
            )
            unary_call = channel.unary_unary(
                rpc_path,
                request_serializer=lambda message: message.SerializeToString(),
                response_deserializer=response_class.FromString,
            )
            response_message, rpc = unary_call.with_call(
                request_message,
                metadata=tuple((str(k), str(v)) for k, v in (metadata or {}).items()),
            )
            response_payload = json_format.MessageToDict(
                response_message, preserving_proto_field_name=True
            )
            initial_metadata = dict(rpc.initial_metadata() or ())
            trailing_metadata = dict(rpc.trailing_metadata() or ())
            return GrpcResponse(
                True,
                service,
                method,
                payload=response_payload,
                metadata={"initial": initial_metadata, "trailing": trailing_metadata},
            )
        except grpc.RpcError as exc:
            code = exc.code().name if exc.code() is not None else "UNKNOWN"
            return GrpcResponse(
                False, service, method, code=code, details=exc.details() or ""
            )
        finally:
            channel.close()
'''


__all__ = ["GRPC_SDK_SOURCE"]
