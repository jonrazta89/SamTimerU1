/*
 * Lightweight Compose utilities to mimic the "liquid glass" aesthetic from
 * Ein UI (https://github.com/einui/einui). The repository uses Tailwind
 * with backdrop-filter, but in Compose we approximate the effect using
 * semi‑transparent surfaces, rounded corners, and a subtle blur.
 */

package com.roottimer.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * A *delicate* glass‑style card.  The constructor accepts a foreground color
 * and an optional background gradient.  The composable is intentionally
 * lightweight – no experimental APIs are used.
 */
@Composable
fun GlassCard(
    modifier: Modifier = Modifier,
    shape: RoundedCornerShape = RoundedCornerShape(16.dp),
    content: @Composable (BoxScope.() -> Unit)
) {
    Surface(
        modifier = modifier
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        Color(0x55FFFFFF),  // 33% opacity white
                        Color(0x30FFFFFF)   // 20% opacity white
                    )
                )
            ),
        shape = shape,
        color = Color.Transparent,
        tonalElevation = 0.dp,
        shadowElevation = 0.dp
    ) {
        Box(modifier = Modifier.padding(12.dp)) {
            content()
        }
    }
}

/**
 * A glass‑style button.  It uses the same surface concept as [GlassCard],
 * but exposes a simple onClick callback like the standard Compose Button.
 */
@Composable
fun GlassButton(
    onClick: () -> Unit,
    enabled: Boolean = true,
    modifier: Modifier = Modifier,
    text: String,
    contentDescription: String? = null,
    shape: RoundedCornerShape = RoundedCornerShape(12.dp)
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.then(
            Modifier
                .background(
                    brush = Brush.linearGradient(
                        colors = listOf(
                            Color(0x66FFFFFF), // 40% opacity
                            Color(0x3FFFFFFF)  // 25% opacity
                        )
                    )
                )
        ),
        shape = shape,
        colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent),
        elevation = ButtonDefaults.buttonElevation(0.dp, 0.dp, 0.dp, 0.dp)
    ) {
        Text(text = text)
    }
}

/**
 * Wake-of‑glass bar – can be used as a top‑app‑bar replacement.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GlassTopAppBar(
    title: String,
    modifier: Modifier = Modifier,
    actions: @Composable RowScope.() -> Unit = {}
) {
    Surface(
        modifier = modifier
            .background(
                brush = Brush.horizontalGradient(
                    colors = listOf(
                        Color(0x48FFFFFF), // 28%
                        Color(0x48FFFFFF)
                    )
                ),
            ),
        color = Color.Transparent,
        tonalElevation = 4.dp
    ) {
        androidx.compose.material3.TopAppBar(
            title = { Text(title) },
            actions = actions,
            colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent)
        )
    }
}

/**
 * A light‑weight glass‑style indicator (similar to a chip).
 */
@Composable
fun GlassChip(
    text: String,
    modifier: Modifier = Modifier,
    shape: RoundedCornerShape = RoundedCornerShape(16.dp),
    textColor: Color = MaterialTheme.colorScheme.onSurface,
    backgroundColor: Color = Color(0x28FFFFFF)
) {
    Surface(
        modifier = modifier,
        shape = shape,
        color = backgroundColor,
        tonalElevation = 0.dp,
        shadowElevation = 0.dp
    ) {
        Box(modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)) {
            Text(text, color = textColor)
        }
    }
}

/* === Helper to support a simple blur effect on Android 13+ (optional) === */
@Composable
fun Modifier.looseBlur(radius: Dp = 10.dp): Modifier {
    // real blur would go here; omitted for compatibility
    return this
}
