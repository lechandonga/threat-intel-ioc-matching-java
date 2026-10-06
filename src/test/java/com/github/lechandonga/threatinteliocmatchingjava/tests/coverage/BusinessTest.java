package com.github.lechandonga.threatinteliocmatchingjava.tests.coverage;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ExtendWith;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 业务测试分组注解：value 为业务名称，测试运行时会按业务打印用例覆盖日志。
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Tag("business")
@ExtendWith(BusinessCoverageExtension.class)
public @interface BusinessTest {
    String value();
}
