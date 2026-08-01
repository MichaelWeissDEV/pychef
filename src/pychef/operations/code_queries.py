"""Safe, standard-library XML, JSON query, and JavaScript parsing operations."""

from __future__ import annotations

import base64
import json
import re
import xml.etree.ElementTree as element_tree
from dataclasses import dataclass
from typing import Any

from ..registry import operation
from ..types import Args, Data, to_text
from ._utils import arg, char_rep


def _serialize(elements: list[element_tree.Element], delimiter: str) -> str:
    serialized: list[str] = []
    for element in elements:
        tail = element.tail
        element.tail = None
        try:
            serialized.append(
                element_tree.tostring(element, encoding="unicode", short_empty_elements=True)
            )
        finally:
            element.tail = tail
    return delimiter.join(serialized)


def _delimiter(value: object) -> str:
    return char_rep(value, "\n").replace("\\r", "\r").replace("\\n", "\n").replace("\\t", "\t")


def _simple_selector_matches(element: element_tree.Element, selector: str) -> bool:
    match = re.fullmatch(r"([A-Za-z][\w:-]*)?(?:#([\w:-]+))?(?:\.([\w:-]+))?", selector)
    if not match:
        raise ValueError(f"unsupported CSS selector component: {selector}")
    tag, element_id, class_name = match.groups()
    classes = element.attrib.get("class", "").split()
    return (
        (tag is None or element.tag == tag)
        and (element_id is None or element.attrib.get("id") == element_id)
        and (class_name is None or class_name in classes)
    )


@operation("CSS selector", category="Code")
def css_selector(value: Data, args: Args) -> str:
    selector = str(arg(args, 0, "")).strip()
    delimiter = _delimiter(arg(args, 1, "Line feed"))
    if not selector:
        return ""
    root = element_tree.fromstring(to_text(value))
    parts = selector.split()
    matches: list[element_tree.Element] = []

    def visit(element: element_tree.Element, ancestors: tuple[element_tree.Element, ...]) -> None:
        if _simple_selector_matches(element, parts[-1]):
            cursor = len(ancestors) - 1
            for component in reversed(parts[:-1]):
                while cursor >= 0 and not _simple_selector_matches(ancestors[cursor], component):
                    cursor -= 1
                if cursor < 0:
                    break
                cursor -= 1
            else:
                matches.append(element)
        for child in element:
            visit(child, (*ancestors, element))

    visit(root, ())
    return _serialize(matches, delimiter)


@operation("XPath expression", category="Code")
def xpath_expression(value: Data, args: Args) -> str:
    expression = str(arg(args, 0, "")).strip()
    delimiter = _delimiter(arg(args, 1, "Line feed"))
    if not expression:
        return ""
    root = element_tree.fromstring(to_text(value))
    root_prefix = f"/{root.tag}"
    if expression == root_prefix:
        matches = [root]
    elif expression.startswith(root_prefix + "/"):
        matches = root.findall("." + expression[len(root_prefix) :])
    elif expression.startswith("/"):
        matches = root.findall("." + expression)
    else:
        matches = root.findall(expression)
    return _serialize(matches, delimiter)


_MISSING = object()


def _json(value: Data) -> Any:
    try:
        return json.loads(to_text(value))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid input JSON: {exc.msg}") from exc


def _split_top(expression: str, separator: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    quote = ""
    escaped = False
    start = 0
    index = 0
    while index < len(expression):
        character = expression[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
        elif character in "'\"`":
            quote = character
        elif character in "([{":
            depth += 1
        elif character in ")]}":
            depth -= 1
        elif depth == 0 and expression.startswith(separator, index):
            parts.append(expression[start:index].strip())
            start = index + len(separator)
            index += len(separator) - 1
        index += 1
    parts.append(expression[start:].strip())
    return parts


def _jq_path(item: Any, expression: str) -> list[Any]:
    if expression == ".":
        return [item]
    if not expression.startswith("."):
        raise ValueError(f"unsupported jq expression: {expression}")
    current = [item]
    position = 1
    while position < len(expression):
        if expression.startswith("[]", position):
            current = [
                entry
                for value in current
                for entry in (value.values() if isinstance(value, dict) else value)
            ]
            position += 2
            continue
        if expression[position] == ".":
            position += 1
            continue
        if expression[position] == "[":
            end = expression.find("]", position)
            if end < 0:
                raise ValueError("unterminated jq index")
            token = expression[position + 1 : end].strip()
            if token.startswith(('"', "'")):
                key = json.loads(token) if token.startswith('"') else token[1:-1]
                current = [value.get(key) for value in current if isinstance(value, dict)]
            else:
                index = int(token)
                current = [
                    value[index]
                    for value in current
                    if isinstance(value, list) and -len(value) <= index < len(value)
                ]
            position = end + 1
            continue
        match = re.match(r"[A-Za-z_$][\w$-]*", expression[position:])
        if match is None:
            raise ValueError(f"invalid jq path near {expression[position:]!r}")
        key = match.group()
        next_values: list[Any] = []
        for value in current:
            if isinstance(value, dict):
                next_values.append(value.get(key))
        current = next_values
        position += len(key)
    return current


def _jq_eval(item: Any, expression: str) -> list[Any]:
    expression = expression.strip()
    alternatives = _split_top(expression, "//")
    if len(alternatives) > 1:
        first = _jq_eval(item, alternatives[0])
        return (
            first
            if first and first[0] not in {None, False}
            else _jq_eval(item, "//".join(alternatives[1:]))
        )
    pipelines = _split_top(expression, "|")
    if len(pipelines) > 1:
        values = [item]
        for pipeline in pipelines:
            values = [result for value in values for result in _jq_eval(value, pipeline)]
        return values
    comma = _split_top(expression, ",")
    if len(comma) > 1:
        return [result for part in comma for result in _jq_eval(item, part)]
    if expression.startswith("select(") and expression.endswith(")"):
        return [item] if _jq_truth(_jq_eval(item, expression[7:-1])) else []
    if expression.startswith("map(") and expression.endswith(")"):
        if not isinstance(item, list):
            raise ValueError("jq map requires an array")
        return [[result for value in item for result in _jq_eval(value, expression[4:-1])]]
    for operator in (
        " == ",
        " != ",
        " >= ",
        " <= ",
        " > ",
        " < ",
        " + ",
        " - ",
        " * ",
        " / ",
        " % ",
    ):
        split = _split_top(expression, operator)
        if len(split) == 2:
            left = _jq_eval(item, split[0])[0]
            right = _jq_eval(item, split[1])[0]
            return [_binary(operator.strip(), left, right)]
    if expression in {
        "length",
        "keys",
        "values",
        "type",
        "tostring",
        "tonumber",
        "add",
        "sort",
        "unique",
        "reverse",
    }:
        if expression == "length":
            return [len(item)]
        if expression == "keys":
            return [sorted(item) if isinstance(item, dict) else list(range(len(item)))]
        if expression == "values":
            return [list(item.values())]
        if expression == "type":
            names = {
                dict: "object",
                list: "array",
                str: "string",
                int: "number",
                float: "number",
                bool: "boolean",
                type(None): "null",
            }
            return [names[type(item)]]
        if expression == "tostring":
            return [item if isinstance(item, str) else json.dumps(item, separators=(",", ":"))]
        if expression == "tonumber":
            return [float(item) if "." in str(item) else int(item)]
        if expression == "add":
            return [sum(item) if item else None]
        if expression == "sort":
            return [sorted(item)]
        if expression == "unique":
            return [list(dict.fromkeys(sorted(item)))]
        return [list(reversed(item))]
    call = re.fullmatch(r"(has|contains)\((.*)\)", expression, re.DOTALL)
    if call:
        argument = _jq_eval(item, call.group(2))[0]
        return [argument in item]
    if expression.startswith("."):
        return _jq_path(item, expression)
    try:
        return [json.loads(expression)]
    except json.JSONDecodeError as exc:
        raise ValueError(f"unsupported jq expression: {expression}") from exc


def _jq_truth(values: list[Any]) -> bool:
    return any(value is not False and value is not None for value in values)


def _binary(operator: str, left: Any, right: Any) -> Any:
    if operator in {"=", "=="}:
        return left == right
    if operator == "!=":
        return left != right
    if operator == "<=":
        return left <= right
    if operator == ">=":
        return left >= right
    if operator == "<":
        return left < right
    if operator == ">":
        return left > right
    if operator == "+":
        return left + right
    if operator == "-":
        return left - right
    if operator == "*":
        return left * right
    if operator == "/":
        return left / right
    if operator == "%":
        return left % right
    if operator == "in":
        return left in right
    if operator == "and":
        return bool(left) and bool(right)
    if operator == "or":
        return bool(left) or bool(right)
    raise ValueError(f"Unsupported binary operator: {operator}")


@operation("Jq", category="Code")
def jq(value: Data, args: Args) -> str:
    query = str(arg(args, 0, "")) or "."
    raw = bool(arg(args, 1, False))
    try:
        results = _jq_eval(_json(value), query)
    except (ValueError, TypeError, KeyError, IndexError, ZeroDivisionError) as exc:
        raise ValueError(f"Invalid jq expression: {exc}") from exc
    result: Any = results[0] if len(results) == 1 else results
    if raw and isinstance(result, str):
        return result
    return json.dumps(result, separators=(",", ":"), ensure_ascii=True)


def _unquote_jsonata(token: str) -> Any:
    if token.startswith("'"):
        return bytes(token[1:-1], "utf-8").decode("unicode_escape")
    return json.loads(token)


def _jsonata_field(value: Any, name: str) -> Any:
    if name == "*":
        if isinstance(value, dict):
            return list(value.values())
        return value
    if isinstance(value, dict):
        return value.get(name, _MISSING)
    if isinstance(value, list):
        output: list[Any] = []
        for item in value:
            selected = _jsonata_field(item, name)
            if selected is _MISSING:
                continue
            if isinstance(selected, list):
                output.extend(selected)
            else:
                output.append(selected)
        return output if output else _MISSING
    return _MISSING


def _deep_field(value: Any, name: str) -> list[Any]:
    output: list[Any] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == name:
                output.append(item)
            output.extend(_deep_field(item, name))
    elif isinstance(value, list):
        for item in value:
            output.extend(_deep_field(item, name))
    return output


def _matching_bracket(expression: str, start: int) -> int:
    depth = 0
    quote = ""
    for index in range(start, len(expression)):
        character = expression[index]
        if quote:
            if character == quote and expression[index - 1] != "\\":
                quote = ""
        elif character in "'\"`":
            quote = character
        elif character == "[":
            depth += 1
        elif character == "]":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("Unterminated JSONata predicate")


def _jsonata_index(value: Any, selector: str, root: Any) -> Any:
    if not isinstance(value, list):
        return value if selector == "0" else _MISSING
    selector = selector.strip()
    range_match = re.fullmatch(r"\[\s*(-?\d+)\s*\.\.\s*(-?\d+)\s*\]", selector)
    if range_match:
        indexes = range(int(range_match.group(1)), int(range_match.group(2)) + 1)
        return [value[index] for index in indexes if -len(value) <= index < len(value)]
    if re.fullmatch(r"-?\d+", selector):
        index = int(selector)
        return value[index] if -len(value) <= index < len(value) else _MISSING
    return [item for item in value if bool(_jsonata_eval(selector, item, root))]


def _jsonata_path(expression: str, context: Any, root: Any) -> Any:
    expression = expression.strip()
    if expression.startswith("**."):
        values = _deep_field(context, expression[3:].strip("`"))
        return values[0] if len(values) == 1 else values
    current = context
    position = 0
    if expression.startswith("$"):
        current = root
        position = 1
    while position < len(expression):
        if expression[position] == ".":
            position += 1
        if position >= len(expression):
            break
        if expression[position] == "(":
            depth = 1
            end = position + 1
            while end < len(expression) and depth:
                depth += (expression[end] == "(") - (expression[end] == ")")
                end += 1
            current = _jsonata_eval(expression[position + 1 : end - 1], current, root)
            position = end
            continue
        if expression[position] == "[":
            end = _matching_bracket(expression, position)
            current = _jsonata_index(current, expression[position + 1 : end], root)
            position = end + 1
            continue
        if expression[position] == "`":
            end = expression.find("`", position + 1)
            if end < 0:
                raise ValueError("Unterminated JSONata field name")
            name = expression[position + 1 : end]
            position = end + 1
        else:
            match = re.match(r"[A-Za-z_][\w ?-]*|\*", expression[position:])
            if match is None:
                raise ValueError(f"Invalid JSONata path near {expression[position:]!r}")
            name = match.group().rstrip()
            position += len(match.group())
        if isinstance(current, list) and position < len(expression) and expression[position] == "[":
            end = _matching_bracket(expression, position)
            selector = expression[position + 1 : end]
            mapped: list[Any] = []
            for item in current:
                selected = _jsonata_field(item, name)
                if selected is not _MISSING:
                    selected = _jsonata_index(selected, selector, root)
                    if selected is not _MISSING:
                        mapped.extend(selected if isinstance(selected, list) else [selected])
            current = mapped if mapped else _MISSING
            position = end + 1
        else:
            current = _jsonata_field(current, name)
        if current is _MISSING:
            return current
    return current


def _outer_parentheses(expression: str) -> bool:
    if not expression.startswith("(") or not expression.endswith(")"):
        return False
    depth = 0
    quote = ""
    for index, character in enumerate(expression):
        if quote:
            if character == quote and expression[index - 1] != "\\":
                quote = ""
        elif character in "'\"":
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0 and index != len(expression) - 1:
                return False
    return depth == 0


def _jsonata_eval(expression: str, context: Any, root: Any) -> Any:
    expression = expression.strip()
    while _outer_parentheses(expression):
        expression = expression[1:-1].strip()
    if expression.startswith(("*.", "**.")) or ".*" in expression:
        return _jsonata_path(expression, context, root)
    for operator in (
        " or ",
        " and ",
        " in ",
        "!=",
        "<=",
        ">=",
        "=",
        "<",
        ">",
        "&",
        "+",
        "-",
        "*",
        "/",
        "%",
    ):
        parts = _split_top(expression, operator)
        if len(parts) > 1:
            values = [_jsonata_eval(part, context, root) for part in parts]
            if operator == "&":
                return "".join(
                    str(value).lower() if isinstance(value, bool) else str(value)
                    for value in values
                )
            left, right = values[0], values[1]
            return _binary(operator.strip(), left, right)
    call = re.fullmatch(r"\$(base64encode|base64decode)\((.*)\)", expression, re.DOTALL)
    if call:
        argument = _jsonata_eval(call.group(2), context, root)
        if call.group(1) == "base64encode":
            return base64.b64encode(str(argument).encode()).decode()
        return base64.b64decode(str(argument)).decode()
    if expression in {"true", "false", "null"}:
        return {"true": True, "false": False, "null": None}[expression]
    if re.fullmatch(r"-?(?:\d+(?:\.\d*)?|\.\d+)", expression):
        return float(expression) if "." in expression else int(expression)
    if len(expression) >= 2 and expression[0] in "'\"" and expression[-1] == expression[0]:
        return _unquote_jsonata(expression)
    return _jsonata_path(expression, context, root)


@operation("Jsonata Query", category="Code")
def jsonata_query(value: Data, args: Args) -> str:
    root = _json(value)
    query = str(arg(args, 0, "string"))
    try:
        result = _jsonata_eval(query, root, root)
    except (ValueError, TypeError, KeyError, IndexError, ZeroDivisionError) as exc:
        raise ValueError(f"Invalid Jsonata Expression: {exc}") from exc
    if result is _MISSING:
        result = ""
    return json.dumps(result, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True, slots=True)
class _JSToken:
    kind: str
    value: str
    start: int
    end: int
    line: int
    column: int


_JS_TOKEN = re.compile(
    r"(?P<space>\s+)|(?P<comment>//[^\r\n]*|/\*[\s\S]*?\*/)|"
    r"(?P<string>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")|"
    r"(?P<number>(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?))|"
    r"(?P<identifier>[A-Za-z_$][\w$]*)|"
    r"(?P<punctuator>===|!==|=>|==|!=|<=|>=|\+\+|--|&&|\|\||\+=|-=|\*\*|.)"
)


def _js_tokens(source: str) -> tuple[list[_JSToken], list[dict[str, Any]]]:
    tokens: list[_JSToken] = []
    comments: list[dict[str, Any]] = []
    for match in _JS_TOKEN.finditer(source):
        kind = match.lastgroup or "punctuator"
        raw = match.group()
        line = source.count("\n", 0, match.start()) + 1
        last_newline = source.rfind("\n", 0, match.start())
        column = match.start() if last_newline < 0 else match.start() - last_newline - 1
        if kind == "space":
            continue
        if kind == "comment":
            comments.append(
                {
                    "type": "Line" if raw.startswith("//") else "Block",
                    "value": raw[2:-2] if raw.startswith("/*") else raw[2:],
                    "range": [match.start(), match.end()],
                }
            )
            continue
        tokens.append(_JSToken(kind, raw, match.start(), match.end(), line, column))
    tokens.append(_JSToken("eof", "", len(source), len(source), source.count("\n") + 1, 0))
    return tokens, comments


class _JSParser:
    def __init__(self, source: str, *, locations: bool, ranges: bool) -> None:
        self.source = source
        self.tokens, self.comments = _js_tokens(source)
        self.position = 0
        self.locations = locations
        self.ranges = ranges

    @property
    def token(self) -> _JSToken:
        return self.tokens[self.position]

    def take(self, value: str | None = None) -> _JSToken:
        token = self.token
        if value is not None and token.value != value:
            raise ValueError(f"Unexpected token {token.value!r}; expected {value!r}")
        self.position += 1
        return token

    def node(self, node_type: str, start: _JSToken, end: _JSToken, **fields: Any) -> dict[str, Any]:
        result = {"type": node_type, **fields}
        if self.ranges:
            result["range"] = [start.start, end.end]
        if self.locations:
            end_line = self.source.count("\n", 0, end.end) + 1
            last = self.source.rfind("\n", 0, end.end)
            result["loc"] = {
                "start": {"line": start.line, "column": start.column},
                "end": {"line": end_line, "column": end.end if last < 0 else end.end - last - 1},
            }
        return result

    def program(self) -> dict[str, Any]:
        start = self.token
        body = []
        while self.token.kind != "eof":
            body.append(self.statement())
        return self.node("Program", start, self.token, body=body, sourceType="script")

    def statement(self) -> dict[str, Any]:
        start = self.token
        if self.token.value in {"var", "let", "const"}:
            kind = self.take().value
            declarations = []
            while True:
                identifier = self.take()
                if identifier.kind != "identifier":
                    raise ValueError(f"Expected JavaScript identifier, got {identifier.value!r}")
                target = self.node("Identifier", identifier, identifier, name=identifier.value)
                initial = None
                end = identifier
                if self.token.value == "=":
                    self.take()
                    initial = self.expression()
                    end = self.tokens[self.position - 1]
                declarations.append(
                    self.node("VariableDeclarator", identifier, end, id=target, init=initial)
                )
                if self.token.value != ",":
                    break
                self.take()
            if self.token.value == ";":
                end = self.take()
            return self.node(
                "VariableDeclaration", start, end, declarations=declarations, kind=kind
            )
        if self.token.value == "return":
            self.take()
            argument = None if self.token.value in {";", "}"} else self.expression()
            end = self.tokens[self.position - 1]
            if self.token.value == ";":
                end = self.take()
            return self.node("ReturnStatement", start, end, argument=argument)
        if self.token.value == "function":
            self.take()
            name = self.take()
            identifier = self.node("Identifier", name, name, name=name.value)
            self.take("(")
            params = []
            while self.token.value != ")":
                parameter = self.take()
                params.append(self.node("Identifier", parameter, parameter, name=parameter.value))
                if self.token.value != ",":
                    break
                self.take()
            self.take(")")
            body = self.block()
            result = self.node(
                "FunctionDeclaration",
                start,
                self.tokens[self.position - 1],
                id=identifier,
                params=params,
                body=body,
                generator=False,
                expression=False,
            )
            result["async"] = False
            return result
        if self.token.value == "{":
            return self.block()
        expression = self.expression()
        end = self.tokens[self.position - 1]
        if self.token.value == ";":
            end = self.take()
        return self.node("ExpressionStatement", start, end, expression=expression)

    def block(self) -> dict[str, Any]:
        start = self.take("{")
        body = []
        while self.token.value != "}":
            if self.token.kind == "eof":
                raise ValueError("Unexpected end of JavaScript block")
            body.append(self.statement())
        end = self.take("}")
        return self.node("BlockStatement", start, end, body=body)

    def expression(self, minimum: int = 0) -> dict[str, Any]:
        start = self.take()
        if start.value == "(":
            left = self.expression()
            self.take(")")
        elif start.kind == "identifier":
            if start.value in {"true", "false", "null"}:
                value = {"true": True, "false": False, "null": None}[start.value]
                left = self.node("Literal", start, start, value=value, raw=start.value)
            else:
                left = self.node("Identifier", start, start, name=start.value)
        elif start.kind in {"string", "number"}:
            value = (
                _unquote_jsonata(start.value)
                if start.kind == "string"
                else (
                    float(start.value)
                    if any(c in start.value for c in ".eE")
                    else int(start.value, 0)
                )
            )
            left = self.node("Literal", start, start, value=value, raw=start.value)
        elif start.value in {"!", "+", "-", "typeof", "void", "delete"}:
            argument = self.expression(12)
            left = self.node(
                "UnaryExpression",
                start,
                self.tokens[self.position - 1],
                operator=start.value,
                prefix=True,
                argument=argument,
            )
        elif start.value == "[":
            elements = []
            while self.token.value != "]":
                elements.append(self.expression())
                if self.token.value != ",":
                    break
                self.take()
            end = self.take("]")
            left = self.node("ArrayExpression", start, end, elements=elements)
        else:
            raise ValueError(f"Unexpected JavaScript token: {start.value!r}")
        precedence = {
            "=": 1,
            "||": 2,
            "&&": 3,
            "==": 4,
            "!=": 4,
            "===": 4,
            "!==": 4,
            "<": 5,
            ">": 5,
            "<=": 5,
            ">=": 5,
            "+": 7,
            "-": 7,
            "*": 8,
            "/": 8,
            "%": 8,
        }
        while True:
            if self.token.value == "(":
                self.take()
                arguments = []
                while self.token.value != ")":
                    arguments.append(self.expression())
                    if self.token.value != ",":
                        break
                    self.take()
                end = self.take(")")
                left = self.node(
                    "CallExpression", start, end, callee=left, arguments=arguments, optional=False
                )
                continue
            if self.token.value == ".":
                self.take()
                prop = self.take()
                property_node = self.node("Identifier", prop, prop, name=prop.value)
                left = self.node(
                    "MemberExpression",
                    start,
                    prop,
                    computed=False,
                    object=left,
                    property=property_node,
                    optional=False,
                )
                continue
            operator = self.token.value
            level = precedence.get(operator, -1)
            if level < minimum:
                break
            self.take()
            right = self.expression(level + (0 if operator == "=" else 1))
            kind = (
                "AssignmentExpression"
                if operator == "="
                else ("LogicalExpression" if operator in {"&&", "||"} else "BinaryExpression")
            )
            left = self.node(
                kind,
                start,
                self.tokens[self.position - 1],
                operator=operator,
                left=left,
                right=right,
            )
        return left


def _strip_ast_options(value: Any, *, locations: bool, ranges: bool) -> None:
    if isinstance(value, dict):
        if not locations:
            value.pop("loc", None)
        if not ranges:
            value.pop("range", None)
        for child in value.values():
            _strip_ast_options(child, locations=locations, ranges=ranges)
    elif isinstance(value, list):
        for child in value:
            _strip_ast_options(child, locations=locations, ranges=ranges)


@operation("JavaScript Parser", category="Code")
def javascript_parser(value: Data, args: Args) -> str:
    source = to_text(value)
    locations = bool(arg(args, 0, False))
    ranges = bool(arg(args, 1, False))
    include_tokens = bool(arg(args, 2, False))
    include_comments = bool(arg(args, 3, False))
    tolerant = bool(arg(args, 4, False))
    parser = _JSParser(source, locations=locations, ranges=ranges)
    try:
        result = parser.program()
    except ValueError as exc:
        if not tolerant:
            raise
        result = parser.node(
            "Program", parser.tokens[0], parser.tokens[-1], body=[], sourceType="script"
        )
        result["errors"] = [{"description": str(exc)}]
    if include_tokens:
        result["tokens"] = [
            {"type": token.kind.title(), "value": token.value, "range": [token.start, token.end]}
            for token in parser.tokens[:-1]
        ]
    if include_comments:
        result["comments"] = parser.comments
    _strip_ast_options(result, locations=locations, ranges=ranges)
    return json.dumps(result, indent=2, ensure_ascii=False)
