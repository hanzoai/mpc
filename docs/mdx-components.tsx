import type { MDXComponents } from "mdx/types"
import {
  defaultMdxComponents,
  Card,
  Cards,
  Tab,
  Tabs,
  Step,
  Steps,
  Callout,
  Accordion,
  Accordions,
  TypeTable,
} from "@hanzo/mdx/components"

export function useMDXComponents(components: MDXComponents): MDXComponents {
  return {
    ...defaultMdxComponents,
    Tab,
    Tabs,
    Card,
    Cards,
    Step,
    Steps,
    Callout,
    Accordion,
    Accordions,
    TypeTable,
    ...components,
  }
}
