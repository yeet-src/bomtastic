import { Link } from "yeetkit";

export default function NotFound(props) {
  return (
    <section class="space-y-3">
      <h1 class="comment">not found</h1>
      <p class="text-dim">
        Nothing is routed at <span class="text-red">{props.path}</span>.
      </p>
      <Link href="/" end class="text-blue hover:underline">
        [back to *home*]
      </Link>
    </section>
  );
}
