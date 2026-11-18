defmodule Scale30.Adapter do
  @moduledoc """
  scale30 Erlang/BEAM adapter — erlang-jose (Elixir থেকে ডাকা), PREREG §3 contract (PREREG_newlangs)।
  ব্যবহার: ./run.sh <cases.json> <outdir> [impl ...]
  load(case) → key (stage=keyload); verify(token, key, algs) → claims (stage=verify)।
  config = README-র নিরাপদ স্বাভাবিক ব্যবহার: `JOSE.JWT.verify_strict(jwk, allowed_algs, token)`।
  erlang-jose claim (exp) যাচাই করে না — সেটা wrapper-এর কাজ (Joken, আলাদা গণ্য নয়)। truth.json কখনো পড়া হয় না।
  JSON codec = jose-এর default (default install-এ OTP `json`)।
  """

  @impls %{
    "erlang-jose" => %{app: :jose, backend: "otp-crypto"}
  }

  def main([cases_path, outdir | names]) do
    {:ok, _} = Application.ensure_all_started(:jose)
    cases = cases_path |> File.read!() |> JSON.decode!() |> Map.fetch!("cases")
    File.mkdir_p!(outdir)
    for n <- if(names == [], do: Map.keys(@impls), else: names) do
      run_one(n, cases, Path.join(outdir, "erlang__#{n}.jsonl"))
      IO.puts(:stderr, "done #{n}")
    end
  end

  defp load("erlang-jose", c) do
    case JOSE.JWK.from_map(c["key"]["jwk"]) do
      %JOSE.JWK{} = k -> k
      other -> raise ArgumentError, "from_map: #{inspect(other, limit: 5)}"
    end
  end

  defp verify("erlang-jose", tok, k, algs) do
    case JOSE.JWT.verify_strict(k, algs, tok) do
      {true, %JOSE.JWT{fields: f}, _jws} -> f
      {false, _, _} -> raise "verify_strict returned false"
      other -> raise "verify_strict: #{inspect(other, limit: 5)}"
    end
  end

  defp err(kind, reason) do
    msg =
      case {kind, reason} do
        {:error, %{__exception__: true} = e} -> "#{inspect(e.__struct__)}: #{Exception.message(e)}"
        _ -> "#{kind}: #{inspect(reason, limit: 8)}"
      end
    String.slice(msg, 0, 200)
  end

  defp now, do: :erlang.monotonic_time(:nanosecond)

  # OTP `json` JSON null-কে atom `:null` হিসেবে দেয়; Elixir `JSON.encode!` সেটাকে string "null" লিখত।
  # ভাষা-জনিত রূপান্তর (ADAPTER_GUIDE §2): `:null` → `nil`, যাতে output-এ আবার JSON null হয়।
  defp json_null(:null), do: nil
  defp json_null(m) when is_map(m), do: Map.new(m, fn {k, v} -> {k, json_null(v)} end)
  defp json_null(l) when is_list(l), do: Enum.map(l, &json_null/1)
  defp json_null(v), do: v

  defp attempt(name, c, k) do
    t0 = now()
    try do
      cl = verify(name, c["token"], k, c["allowed_algs"])
      ns = now() - t0
      if is_map(cl),
        do: %{"accepted" => true, "claims" => json_null(cl), "stage" => "verify", "ns" => ns},
        else: %{"stage" => "claims", "error" => "non-map claims", "ns" => ns}
    catch
      kind, reason -> %{"stage" => "verify", "error" => err(kind, reason), "ns" => now() - t0}
    end
  end

  defp run_one(name, cases, out) do
    %{app: app, backend: backend} = @impls[name]
    base = %{"impl" => "erlang/#{name}", "version" => to_string(Application.spec(app, :vsn)),
             "lang" => "erlang", "backend" => backend}
    lines =
      cases
      |> Enum.with_index()
      |> Enum.map(fn {c, i} ->
        r = Map.merge(base, %{"case" => c["id"], "accepted" => false, "claims" => %{}, "error" => "",
                              "stage" => "", "ns" => 0})
        r =
          try do
            {:ok, load(name, c)}
          catch
            kind, reason -> {:keyload, err(kind, reason)}
          end
          |> case do
            {:keyload, e} -> %{r | "stage" => "keyload", "error" => e}
            {:ok, k} ->
              r = Map.merge(r, attempt(name, c, k))
              # প্রথম call-এ lazy init — আবার মাপা
              if i == 0, do: %{r | "ns" => attempt(name, c, k)["ns"]}, else: r
          end
        [JSON.encode!(r), "\n"]
      end)
    File.write!(out, lines)
  end
end
