package net.bytebutcher.burpautodropextension.models;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

public class AutoDropRequestRule {

    private String id = UUID.randomUUID().toString();
    private EBooleanOperator booleanOperator;
    private EMatchType matchType;
    private EMatchRelationship matchRelationship;
    private Pattern matchCondition;
    private boolean isEnabled;
    public AutoDropRequestRule(EBooleanOperator booleanOperator, EMatchType matchType, EMatchRelationship matchRelationship, String matchCondition, boolean isEnabled) {
        this.booleanOperator = booleanOperator;
        this.matchType = matchType;
        this.matchRelationship = matchRelationship;
        this.matchCondition = matchCondition != null ? Pattern.compile(matchCondition) : Pattern.compile("");
        this.isEnabled = isEnabled;
    }
    public AutoDropRequestRule(String id, EBooleanOperator booleanOperator, EMatchType matchType, EMatchRelationship matchRelationship, String matchCondition, boolean isEnabled) {
        this(booleanOperator, matchType, matchRelationship, matchCondition, isEnabled);
        this.id = id;
    }

    public String getId() {
        return this.id;
    }

    public EBooleanOperator getBooleanOperator() {
        return this.booleanOperator;
    }

    public EMatchType getMatchType() {
        return this.matchType;
    }

    public EMatchRelationship getMatchRelationship() {
        return matchRelationship;
    }

    public Pattern getMatchCondition() {
        return this.matchCondition;
    }

    public boolean isEnabled() {
        return isEnabled;
    }

    @Override
    public String toString() {
        return "AutoDropRequestRule{" +
                "id='" + id + '\'' +
                ", booleanOperator=" + booleanOperator +
                ", matchType=" + matchType +
                ", matchRelationship=" + matchRelationship +
                ", matchCondition=" + matchCondition +
                ", isEnabled=" + isEnabled +
                '}';
    }

    public enum EBooleanOperator {
        AND(0, "And"),
        OR(1, "Or");

        private int index;
        private String name;

        EBooleanOperator(int index, String name) {
            this.index = index;
            this.name = name;
        }

        public static Optional<EBooleanOperator> byIndex(int value) {
            return Arrays.stream(values())
                    .filter(booleanOperator -> booleanOperator.index == value)
                    .findFirst();
        }

        public static Optional<EBooleanOperator> byName(String value) {
            return Arrays.stream(values())
                    .filter(booleanOperator -> Objects.equals(booleanOperator.name, value))
                    .findFirst();
        }

        public int getIndex() {
            return this.index;
        }

        public String getName() {
            return this.name;
        }
    }

    public enum EMatchType {
        DOMAIN_NAME(0, "Domain name"),
        IP_ADDRESS(1, "IP address"),
        PROTOCOL(2, "Protocol"),
        HTTP_METHOD(3, "HTTP method"),
        URL(4, "URL"),
        FILE_EXTENSION(5, "File extension"),
        REQUEST(6, "Request"),
        COOKIE_NAME(7, "Cookie name"),
        COOKIE_VALUE(8, "Cookie value"),
        ANY_HEADER(9, "Any header"),
        BODY(10, "Body"),
        PARAM_NAME(11, "Param name"),
        PARAM_VALUE(12, "Param value"),
        LISTENER_PORT(13, "Listener port");

        private int index;
        private String name;

        EMatchType(int index, String name) {
            this.index = index;
            this.name = name;
        }

        public static Optional<EMatchType> byIndex(int value) {
            return Arrays.stream(values())
                    .filter(matchType -> matchType.index == value)
                    .findFirst();
        }

        public static Optional<EMatchType> byName(String value) {
            return Arrays.stream(values())
                    .filter(matchType -> Objects.equals(matchType.name, value))
                    .findFirst();
        }

        public int getIndex() {
            return this.index;
        }

        public String getName() {
            return name;
        }
    }

    public enum EMatchRelationship {
        MATCHES(0, "Matches"),
        DOES_NOT_MATCH(1, "Does not match");

        private int index;
        private String name;

        EMatchRelationship(int index, String name) {
            this.index = index;
            this.name = name;
        }

        public static Optional<EMatchRelationship> byIndex(int value) {
            return Arrays.stream(values())
                    .filter(matchRelationship -> matchRelationship.index == value)
                    .findFirst();
        }

        public static Optional<EMatchRelationship> byName(String value) {
            return Arrays.stream(values())
                    .filter(matchRelationship -> Objects.equals(matchRelationship.name, value))
                    .findFirst();
        }

        public int getIndex() {
            return this.index;
        }

        public String getName() {
            return name;
        }
    }

}
