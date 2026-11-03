package com.undercode.sniffer

import android.content.Context
import android.content.SharedPreferences

/** Preferencias simples (reglas activas, listas de confianza/bloqueo, selección). */
object Prefs {
    private var sp: SharedPreferences? = null

    fun init(ctx: Context) {
        if (sp == null) {
            sp = ctx.applicationContext.getSharedPreferences("sniffer", Context.MODE_PRIVATE)
        }
    }

    fun bool(key: String, def: Boolean): Boolean = sp?.getBoolean(key, def) ?: def
    fun setBool(key: String, v: Boolean) {
        sp?.edit()?.putBoolean(key, v)?.apply()
    }

    fun str(key: String): String? = sp?.getString(key, null)
    fun setStr(key: String, v: String?) {
        sp?.edit()?.putString(key, v)?.apply()
    }

    fun long(key: String, def: Long = 0L): Long = sp?.getLong(key, def) ?: def
    fun setLong(key: String, v: Long) {
        sp?.edit()?.putLong(key, v)?.apply()
    }

    fun set(key: String): MutableSet<String> {
        val s = sp?.getStringSet(key, null)
        return if (s == null) HashSet() else HashSet(s)
    }

    fun setSet(key: String, v: Set<String>) {
        sp?.edit()?.putStringSet(key, HashSet(v))?.apply()
    }
}
