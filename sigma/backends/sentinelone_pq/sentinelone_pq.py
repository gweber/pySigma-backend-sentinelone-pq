from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.processing.pipeline import ProcessingPipeline
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression
from sigma.types import SigmaCompareExpression, SigmaRegularExpression, SigmaString
from sigma.pipelines.sentinelone_pq import sentinelonepq_pipeline
from sigma.conversion.deferred import DeferredQueryExpression
import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Union

class SentinelOnePQBackend(TextQueryBackend):
    """SentinelOne PowerQuery backend."""

    backend_processing_pipeline: ClassVar[ProcessingPipeline] = sentinelonepq_pipeline()

    name : ClassVar[str] = "SentinelOne PowerQuery backend"
    formats : Dict[str, str] = {
        "default": "Plaintext",
        "json": "JSON format"
    }

    requires_pipeline : bool = False

    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    parenthesize : bool = True
    group_expression : ClassVar[str] = "({expr})"

    token_separator : str = " "
    or_token : ClassVar[str] = "or"
    and_token : ClassVar[str] = "and"
    not_token : ClassVar[str] = "not"
    eq_token : ClassVar[str] = "="
    # Sigma matches strings case-insensitively. In PowerQuery `=` and `in` compare case-sensitively,
    # `in:anycase` does not, so a string equals is written as a one-value in:anycase list. Numbers
    # keep eq_token.
    eq_expression : ClassVar[str] = "{field} in:anycase ({value})"

    field_quote : ClassVar[str] = "'"
    field_quote_pattern : ClassVar[Pattern] = re.compile(r"^\w\.+$")
    field_quote_pattern_negation : ClassVar[bool] = False

    field_escape : ClassVar[str] = "\\"
    field_escape_quote : ClassVar[bool] = True
    field_escape_pattern : ClassVar[Pattern] = re.compile("\\s")

    str_quote       : ClassVar[str] = '"'
    escape_char     : ClassVar[str] = "\\"
    wildcard_multi  : ClassVar[str] = "*"
    wildcard_single : ClassVar[str] = "*"
    add_escaped     : ClassVar[str] = "\\"
    filter_chars    : ClassVar[str] = ""
    bool_values     : ClassVar[Dict[bool, str]] = {
        True: "true",
        False: "false",
    }

    # startswith/endswith as anchored regular expressions: `contains` also matched the value in the middle
    # (endswith "\\svchost.exe" matched paths continuing after it). PowerQuery's matches is case-insensitive,
    # as Sigma's string matching is.
    startswith_expression : ClassVar[str] = "{field} matches \"^{regex}\""
    endswith_expression   : ClassVar[str] = "{field} matches \"{regex}$\""
    # A value with wildcards inside it ("a*b") as one anchored regular expression, the wildcards as ".*".
    wildcard_match_expression : ClassVar[str] = "{field} matches \"^{regex}$\""
    contains_expression   : ClassVar[str] = "{field} contains {value}"

    re_expression : ClassVar[str] = "{field} matches \"{regex}\""
    re_escape_char : ClassVar[str] = "\\"
    # Characters to escape in regex. The double quote ends the PowerQuery string the regex is written in:
    # a regex holding one (`\.bat" list`) was cut there and the query refused ("Start quote with no matching end quote").
    re_escape : ClassVar[Tuple[str]] = ("\\(", "\\)", "\\[", "\\]", "\\{", "\\}", "\\.", "\\*", "\\+", "\\?", "\\|", "\\^", "\\$", '"',)
    re_escape_escape_char : bool = True
    re_flag_prefix : bool = False

    # Case sensitive string matching expression. String is quoted/escaped like a normal string.
    # Placeholders {field} and {value} are replaced with field name and quoted/escaped string.
    case_sensitive_match_expression : ClassVar[str] = "{field} == {value}"
    # Case sensitive string matching operators similar to standard string matching. If not provided,
    # case_sensitive_match_expression is used.
    case_sensitive_startswith_expression : ClassVar[str] = "{field} contains:matchcase {value}"
    case_sensitive_endswith_expression   : ClassVar[str] = "{field} contains:matchcase {value}"
    case_sensitive_contains_expression   : ClassVar[str] = "{field} contains:matchcase {value}"

    compare_op_expression : ClassVar[str] = "{field} {operator} {value}"
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    field_null_expression : ClassVar[str] = 'not ({field}=*)'

    field_exists_expression : ClassVar[str] = '{field} = *'                # Expression for field existence as format string with {field} placeholder for field name
    field_not_exists_expression : ClassVar[str] = 'not ({field} = *)'      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.

    convert_or_as_in : ClassVar[bool] = True                      # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = False                    # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = False       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[str] = "in:anycase"       # Operator used to convert OR into in-expressions (case-insensitive, as Sigma matches)
    list_separator : ClassVar[str] = ","               # List element separator

    unbound_value_str_expression : ClassVar[str] = '"{value}"'
    unbound_value_num_expression : ClassVar[str] = '"{value}"'

    # Correlation rules (Sigma 2): the matching events grouped into time buckets and the groups filtered on
    # their count. PowerQuery's timebucket('<span>') takes Sigma's timespans as written (30s, 5m, 1h, 1d were
    # measured). value_count is exact: PowerQuery's estimate_distinct() is an estimate, so the distinct values
    # are grouped first and the groups counted. Temporal correlations are not supported: they need each event
    # marked with the rule it matched, which a PowerQuery filter cannot do.
    correlation_methods : ClassVar[Dict[str, str]] = {
        "default": "Events grouped into time buckets (timebucket), the groups filtered on their count",
    }
    default_correlation_method : ClassVar[str] = "default"
    default_correlation_query : ClassVar[Dict[str, str]] = {"default": "{search} {aggregate} {condition}"}
    correlation_search_single_rule_expression : ClassVar[str] = "{query}"
    correlation_search_multi_rule_expression : ClassVar[str] = "{queries}"
    correlation_search_multi_rule_query_expression : ClassVar[str] = "({query})"
    correlation_search_multi_rule_query_expression_joiner : ClassVar[str] = " or "
    correlation_search_field_normalization_expression : ClassVar[str] = ""
    correlation_search_field_normalization_expression_joiner : ClassVar[str] = ""
    event_count_aggregation_expression : ClassVar[Dict[str, str]] = {
        "default": "| group event_count = count() by timebucket = timebucket('{timespan}'){groupby}",
    }
    value_count_aggregation_expression : ClassVar[Dict[str, str]] = {
        "default": "| group events = count() by timebucket = timebucket('{timespan}'){groupby}, {field} "
                   "| group value_count = count() by timebucket{groupby}",
    }
    groupby_expression : ClassVar[Dict[str, str]] = {"default": ", {fields}"}
    groupby_field_expression : ClassVar[Dict[str, str]] = {"default": "{field}"}
    groupby_field_expression_joiner : ClassVar[Dict[str, str]] = {"default": ", "}
    event_count_condition_expression : ClassVar[Dict[str, str]] = {"default": "| filter event_count {op} {count}"}
    value_count_condition_expression : ClassVar[Dict[str, str]] = {"default": "| filter value_count {op} {count}"}

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> Union[str, DeferredQueryExpression, None]:
        """A negated single comparison is written in parentheses. PowerQuery binds `not` to the field name:
        `not tgt.process.cmdline contains "x"` matched no event at all, `not (tgt.process.cmdline contains "x")`
        everything without "x". pySigma groups only a negated and/or."""
        arg = cond.args[0]
        if arg is None or arg.__class__ in self.precedence:
            return super().convert_condition_not(cond, state)
        expr = self.convert_condition(arg, state)
        if isinstance(expr, DeferredQueryExpression):
            return expr.negate()
        if expr is None:
            return None
        return self.not_token + self.token_separator + self.group_expression.format(expr=expr)

    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        query += ' | columns ' + ",".join(rule.fields) if rule.fields else ''
        return query

    def finalize_output_default(self, queries: List[str]) -> str:
        return queries

    def finalize_query_json(self, rule: SigmaRule, query: str, index: int, state:ConversionState) -> dict:
        query += ' | columns ' + ",".join(rule.fields) if rule.fields else ''
        return {"query":query, "title":rule.title, "id":rule.id, "description": rule.description}
    
    def finalize_output_json(self, queries: List[str]) -> dict:
        return {"queries":queries}
    
    